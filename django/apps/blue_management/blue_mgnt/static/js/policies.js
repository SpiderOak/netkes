(function() {
    function editableByInheritance(event) {
        var select = event.target;
        console.log(event);
        if (select.value === '--inherit--') {
            $(select).parent().siblings('td').children()[0].disabled = true;
        } else {
            $(select).parent().siblings('td').children()[0].disabled = false;
        }
    }

    function updateInheritanceSelection(event) {
        console.log(event);
        var input = event.target;
        var inheritance = $(input).parent().siblings('td').children('select')[0];

        if (inheritance.value === '--unset--') {
            inheritance.value = '--set--';
        }
    }

    $('.policy-inherit-select').each(function() {
        editableByInheritance({'target': this});
        $(this).change(editableByInheritance);

        $($(this).parent().siblings('td').children()[0]).change(updateInheritanceSelection);
    })

})();