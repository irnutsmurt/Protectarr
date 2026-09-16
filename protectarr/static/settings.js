/* Per-card unsaved-changes state for Settings.
 *
 * One card is one <form> is one save boundary, so unsaved state is per form
 * too. Several cards can be dirty at once and each saves on its own; there is
 * deliberately no control anywhere that looks like it saves the page, because
 * there is no endpoint behind one.
 *
 * Dirty is decided from the browser's own record of what the server sent:
 * `defaultValue`, `defaultChecked`, `defaultSelected`. No snapshot of form
 * values is taken and none is needed, which is what keeps stored secrets out of
 * this entirely. The password field renders blank, so its default is blank:
 * typing into it is dirty, leaving it alone is clean, and the stored hash never
 * has to be known to work that out.
 *
 * Discard is `form.reset()`, which restores exactly those same defaults. The
 * one thing reset cannot undo is a row added or removed from the DOM, so a
 * container marked `data-restore-on-discard` has a clone kept from page load
 * and put back. That clone is path-mapping markup; nothing secret is held here.
 * A page reload is not used: it would throw away edits in every *other* dirty
 * card, which is the opposite of per-card.
 *
 * Presentation only. The server remains the authority on what is saved, and
 * nothing here touches the saved-state chips: those describe the config on
 * disk, and following an unsaved edit would make them answer a different
 * question from the one they look like they answer.
 */
(function () {
  var FORMS = 'form[action^="/settings/"][action$="/save"]';
  var forms = Array.prototype.slice.call(document.querySelectorAll(FORMS));
  if (!forms.length) return;

  // Tells the stylesheet the enhanced controls exist, so the in-body Save can
  // be hidden. Without JavaScript the class is never added and that button
  // stays exactly where it has always been.
  document.documentElement.classList.add('has-dirty-ui');

  function fields(form) {
    return Array.prototype.filter.call(form.elements, function (el) {
      return el.name && el.name !== 'csrf_token' &&
             el.type !== 'submit' && el.type !== 'button';
    });
  }

  function changed(el) {
    if (el.type === 'checkbox' || el.type === 'radio') {
      return el.checked !== el.defaultChecked;
    }
    if (el.tagName === 'SELECT') {
      for (var i = 0; i < el.options.length; i++) {
        if (el.options[i].selected !== el.options[i].defaultSelected) return true;
      }
      return false;
    }
    return el.value !== el.defaultValue;
  }

  function isDirty(form) {
    if (fields(form).some(changed)) return true;
    // A row added or removed is a change no default can describe.
    return Array.prototype.some.call(
      form.querySelectorAll('[data-restore-on-discard]'), function (box) {
        return box.children.length !== Number(box.dataset.rowCount);
      });
  }

  function strip(form, card) {
    var bar = document.createElement('div');
    bar.className = 'dirtybar';
    bar.hidden = true;

    var msg = document.createElement('span');
    msg.className = 'dirtymsg';
    msg.textContent = 'Unsaved changes';
    // Announced rather than only coloured, and polite so it waits for a pause
    // in typing instead of interrupting every keystroke.
    msg.setAttribute('role', 'status');
    msg.setAttribute('aria-live', 'polite');

    var discard = document.createElement('button');
    discard.type = 'button';
    discard.className = 'btn small';
    discard.textContent = 'Discard';

    var save = document.createElement('button');
    save.type = 'submit';          // inside the form already, so no form=
    save.className = 'btn small primary';
    save.textContent = form.dataset.saveLabel || 'Save';

    bar.appendChild(msg);
    bar.appendChild(discard);
    bar.appendChild(save);
    card.querySelector('h2').appendChild(bar);
    return {bar: bar, discard: discard};
  }

  forms.forEach(function (form) {
    var card = form.querySelector('.card');
    if (!card) return;
    var ui = strip(form, card);
    var submitting = false;

    Array.prototype.forEach.call(
      form.querySelectorAll('[data-restore-on-discard]'), function (box) {
        box.dataset.rowCount = box.children.length;
        box._pristine = box.cloneNode(true);
      });

    function paint() {
      var dirty = !submitting && isDirty(form);
      card.classList.toggle('dirty', dirty);
      form.classList.toggle('is-dirty', dirty);
      ui.bar.hidden = !dirty;
    }

    ui.discard.addEventListener('click', function () {
      form.reset();
      Array.prototype.forEach.call(
        form.querySelectorAll('[data-restore-on-discard]'), function (box) {
          var fresh = box._pristine.cloneNode(true);
          fresh.dataset.rowCount = box.dataset.rowCount;
          fresh._pristine = box._pristine;
          box.parentNode.replaceChild(fresh, box);
          watch(fresh);
          // The card owns whatever else depends on those rows.
          fresh.dispatchEvent(new CustomEvent('protectarr:restored',
                                              {bubbles: true}));
        });
      paint();
    });

    // `input` covers typing, `change` covers checkboxes and selects. Both
    // bubble, so one listener per form catches controls that do not exist yet
    // (the category, tag and indexer lists arrive from a fetch).
    form.addEventListener('input', paint);
    form.addEventListener('change', paint);
    form.addEventListener('submit', function () {
      submitting = true;          // do not warn about leaving on our own save
      paint();
    });

    // Add mapping / Remove fire neither input nor change.
    //
    // Both listeners are needed and neither is redundant. A click bubbles to
    // the form after the inline handler has run, which repaints immediately
    // when a row is added. Removing a row detaches the button mid-dispatch, so
    // that click never reaches the form and only the observer sees it. The
    // observer runs a microtask later, which is why it is the fallback rather
    // than the whole mechanism.
    form.addEventListener('click', paint);
    function watch(box) {
      new MutationObserver(paint).observe(box, {childList: true});
    }
    Array.prototype.forEach.call(
      form.querySelectorAll('[data-restore-on-discard]'), watch);

    paint();
  });

  // The only mechanism that catches a nav link, the back button and a typed
  // URL alike. Registered once and asked each time rather than toggled, so it
  // cannot get stuck on after the last card is saved.
  window.addEventListener('beforeunload', function (e) {
    if (!document.querySelector('form.is-dirty')) return;
    e.preventDefault();
    e.returnValue = '';
  });
})();
