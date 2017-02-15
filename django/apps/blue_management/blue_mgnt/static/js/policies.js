(function () {
  "use strict";

  function hideEmptyTables() {
    $('.child-table').each(function() {
      if ($(this).children().children('tr').filter(function() { 
        return $(this).css('display') !== 'none'; 
      }).length === 0) {
        $(this).hide();
        $(this).parent().parent().hide();
      } else {
        $(this).show();
        $(this).parent().parent().show();
      }
    });
  }

  function changeVisibiltyOnParentCondition(event) {
    var parent = event.target;
    var parent_name = parent.id.substring(3); // remove id_ from parent id

    $("[data-parent='{}']".replace("{}", parent_name)).each(function () {
      console.log(parent.value);
      console.log($(this).data('conditional-parent-value'));
      var parentVisible = $(parent).is(":visible");

      if ($(this).data("conditional-parent-value") === parent.value && parentVisible) {
        $(this).parent().parent().show();
      } else if ($(this).data("conditional-parent-value").indexOf(parent.value) > -1 && parentVisible) {
        // Check if parent value is in a list of accepted values
        $(this).parent().parent().show();
      } else if ($(this).data("conditional-parent-value") === "True" && $(parent).is(":checked") && parentVisible) {
        // if conditional value is true and the checkbox is checked, show this child
        $(this).parent().parent().show(); // this should show the table row
      } else {
        $(this).parent().parent().hide(); // this should hide the table row
      }
      hideEmptyTables();
      $(this).change();
    });
  }

  $("[data-parent]").each(function () {
    var parent = $("#id_" + $(this).data("parent"));
    parent.change(changeVisibiltyOnParentCondition);
    parent.change();
  });


  function editableByInheritance(event) {
    // use this function to make the field editable or read only
    var select = event.target;

    if (select.value === "--inherit--") {
      $(select).parent().siblings("td").children()[0].disabled = true;
    } else {
      $(select).parent().siblings("td").children()[0].disabled = false;
    }
  }

  function updateInheritanceSelection(event) {
    // Changes --unset-- inheritance to --set-- when the field value is updated
    var input = event.target;
    var inheritance = $(input).parent().siblings("td").children("select")[0];

    if (inheritance.value === "--unset--") {
      inheritance.value = "--set--";
    }
  }

  $(".policy-inherit-select").each(function () {
    /* bind functions to thier events and run editableByInheritance
        when the page loads */
    $(this).change(editableByInheritance);
    // Trigger the change event
    $(this).change();

    $($(this).parent().siblings("td").children()[0]).change(updateInheritanceSelection);

  });

})();
