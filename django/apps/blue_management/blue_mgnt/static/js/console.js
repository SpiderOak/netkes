$(function() {
    // Usage Bar
    // Adjusted to add classes when the amount used exceeds 
    // 50% (yellow) and 90% (red with "Almost out of space!" message).
    // Show usage bar @ 3% if used_num is less than 1% - Just for show.
    if(used_num || allocated_num) {
        test_num = 36814260000000; // FOR TESTING
        // Replace used_num with test_num for testing values.
        pos_adjust = Math.round((used_num / allocated_num) * 100);

        if (pos_adjust <= 1) {
            pos_adjust = 3;
        } else if (pos_adjust >= 48 && pos_adjust <= 89){
            $('.usage-bar-space-used').addClass('usage-warning');
        } else if (pos_adjust >= 90) {
            $('.usage-bar-space-used').addClass('usage-danger');
            $('.usage-bar-space-used').html('<span>Almost out of space!</span>');
        }

        pos_convert = 518 * (pos_adjust / 100); // Converts the % to something useful.
        new_pos = -518 + pos_convert; // Sets the bar

        $('.usage-bar-space-used').css('left', new_pos);
    } else {
        var used_num = 0;
        var allocated_num = 0;
    }

    // Workings for the modal wrapper and widgets

    $('#add-widget').click(function(){
        $('.modal-wrapper').show().css('height', $(document).height());
    });

    $('#option-add-user button').click(function(){
            $('.widget-add-user-option').hide();
            $('.widget-add-user').show();
    });

    $('h2.page-header .actions').click(function() {
        $('.widget-add-user').hide()
        $('.widget-add-user-option').show();
        $('.modal-wrapper').hide();
    });

    //Auto Tooltips
    $('td').each(function(){
        if($(this).text()){
            if(this.offsetWidth < this.scrollWidth){
                $(this).attr('title', $(this).text());
            }
        }
    });

    //Loader for the login page
    $('#login').mouseup(function() {
        $(this).replaceWith("<img src='/static/blue_mgnt/img/loader.gif' style='float:right; margin-right:40px'/>");
        $('#log_in').submit();
    });

function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie != '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = jQuery.trim(cookies[i]);
            // Does this cookie string begin with the name we want?
            if (cookie.substring(0, name.length + 1) == (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
var csrftoken = getCookie('csrftoken');
});
