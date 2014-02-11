$(function() {
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


    // Status
    $('.status-message .actions').click(function() {
        $('.status-message').css('display', 'none');
    });

    //Auto Tooltips
    $('td').each(function(){
        if($(this).text()){
            if(this.offsetWidth < this.scrollWidth){
                $(this).attr('title', $(this).text());
            }
        }
    });

    //Loading shield for submit buttons
    $('.shield').hide();
    
    $('input[type=submit]').click(function(e) {
        e.preventDefault();
        $('body').css({
            'position' : 'relative',
            'z-index' : '1',
            'cursor' : 'wait'
        });
        $('.shield').css({
            'position' : 'absolute',
            'z-index' : '10000'
        }).toggle();
        
        $(this).parent('form').submit();
    });


    // Controller for hide/show in details
    if($('toggle-controller')){
        $('.widget-overview').hide()
        $('.toggle-controller > span').html('<i class="ss-icon">&#x002B;</i> See');
        $('.toggle-controller').click(function(){
            var curr_widget = $(this).parent().next('.widget-overview');
            curr_widget.toggle();
            $('span', this).html(curr_widget.is(':visible') ? '<i class="ss-icon">&#x002D;</i> Hide' : '<i class="ss-icon">&#x002B;</i> See');
        });
    }

    // Toggle permissions in group_detail and add-group-widget
    if($('#id_admin_group').prop('checked')) {
        $('.permissions').show();
    } else {
        $('.permissions').hide();
    }
    $('#id_admin_group').click(function() {
        $('.permissions').toggle(this.checked);
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
