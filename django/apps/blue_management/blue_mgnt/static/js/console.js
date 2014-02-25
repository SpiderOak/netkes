$(function() {
    // Workings for the modal wrapper and widgets

    function posModal(obj) {
        obj = $(obj);
        if ( obj.is(':visible') ) {

            pos_left = Math.round(($(window).width() - obj.outerWidth()) / 2) + ($(document).scrollLeft());
            pos_top = Math.round(($(window).height() - obj.outerHeight()) / 2) + ($(document).scrollTop());

            obj.css({
                'left' : pos_left,
                'top' : pos_top
            });
        }
    }

    $('#add-widget').click(function(){
        $('.modal-wrapper').show().css('height', $(document).height());
        posModal('.modal-content');
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

    // Confirm delete
    $('.cancel-action').click(function() {
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
        });
        $('.shield').css({
            'position' : 'absolute',
            'z-index' : '10000'
        }).toggle();
        
        posModal('.loader');
        
        $(this).closest('form').submit();
        
        if ($('.modal-wrapper').is(':visible')) {
            $('.modal-wrapper').hide();
        }
    });


    // Adjust table widths
/*    $('td').each(function(){
        $th = $('td').closest('table').find('th').eq($(this).index() -1);
        if( $(this).has('input').length ) {
            $th.css('width', '180px');
        }

    });
*/
    // Toggle long logs
    if ( $('body').hasClass('logs') ){
        $('td').each(function() {
            var start = $('.start-pos', this).get(0).getClientRects();
            var end = $('.end-pos', this).get(0).getClientRects();
            if( start.length > (end.length + 1) ) {
                $(this).prepend('<span class="ss-icon log-toggle">&#x002B;</span>');
                $(this).addClass('collapse');
                $(this).closest('table').css('table-layout', 'fixed');
            }
        });

        $('.log-toggle').click(function() {
            $(this).closest('td').toggleClass('collapse');
            $(this).html($(this).closest('td').hasClass('collapse') ? '<i class="ss-icon">&#x002B;</i>' : '<i class="ss-icon">&#x002D;</i>');
        });
    }

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
