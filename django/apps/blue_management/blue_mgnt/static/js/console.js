function posModal(obj) {
    obj = $(obj);
    if ( obj.is(':visible') ) {
        
        if ( obj.css('left') > 0 ) {
            obj.css({
                'left' : '0',
                'top' : '0'
            });
        }

        pos_left = Math.round(($(window).width() - obj.outerWidth()) / 2) + ($(document).scrollLeft());
        pos_top = Math.round(($(window).height() - obj.outerHeight()) / 2) + ($(document).scrollTop());

        obj.css({
            'left' : pos_left,
            'top' : pos_top,
            'z-index' : '10000'
        });
    }
}

$(function() {
    // Shorten numeric inputs
    $(window).load(function() {
        $input = $("input[type='text']").not('.widget-search-input, #id_username, #promo_code_field');
        var $size;
        $input.each(function() {
            if ( $(this).val().length < 1 ) {
                $size = 25;
            } else {
                $size = $(this).val().length;
            }
            var size_calc = $size <= 8 ? 10 : ($size + 5);
            $(this).css('width', 'auto').attr('size', size_calc);
        });
    });
    
    // Toggle for column filter
    $('#filter-columns').click(function(){
        var $fm = $('.filter-menu');
        if ($fm.attr('data-visibility') == 'false') {
            $fm.css('visibility', 'visible').attr('data-visibility', 'true');
        } else {
            $fm.css('visibility', 'hidden').attr('data-visibility', 'false');
        }
    });

    // Workings for the modal wrapper and widgets

    if ( $('.modal-content span').hasClass('error-highlight') ) {
        $('.modal-wrapper').show().css('height', $(document).height());
        posModal('.modal-content');
        if ($('.widget-add-user .error-highlight').length) {
            $('.widget-add-user').show();
        }
        if ($('.widget-upload-csv .error-highlight').length) {
            $('.widget-upload-csv').show();
        }
    }

    $('#add-widget').click(function(e){ //TODO: Depreciate this
        e.preventDefault();
        $('.modal-wrapper').show().css('height', $(document).height());
        posModal('.modal-content');
    });

    $('[id^=modal-trigger-]').click(function(e) {
        e.preventDefault();
        var this_id = $(this).attr('id');
        var this_name = this_id.lastIndexOf('-');
        var this_refer = '#modal-refer-' + this_id.substring(this_name + 1);
        console.log(this_id + ',' + this_refer);

        var other_modals = $('[id^=modal-refer-]').not(this_refer);
        if ( other_modals.is(':visible') ){
            other_modals.hide();
        }
        
        $(this_refer).closest('.modal-wrapper').show().css('height', $(document).height());
        $(this_refer).show();
        posModal(this_refer);
    });

    (function() {
        function exposeWidget(trgt){
            var $modal = $('.modal-wrapper');
            $(".modal-item", $modal).each(function(i, el) {
                $el = $(el);
                $el.toggle($el.hasClass(trgt));
            });
            $modal.show().css('height', $(document).height());
            posModal('.modal-content');
        }

        $('#option-add-user button').click(function(e){
            e.preventDefault();
            exposeWidget('widget-add-user');
        });

        $('#option-upload-csv button').click(function(e){
            e.preventDefault();
            exposeWidget('widget-upload-csv');
        });
    }());

    $('h2.page-header .actions').click(function() {
        var thing = $(this).closest('[id^=modal-refer-]');
        thing.hide();
        console.log(thing.attr('id') + ' was hidden.');
        $('.widget-add-user').hide()
        $('.widget-upload-csv').hide();
        $('.modal-wrapper .modal-item').hide();
        $('.modal-wrapper').hide();
    });

    // Confirm delete
    $('.cancel-action').click(function() {
        $(this).closest('[id^=modal-refer-]').hide();
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

    $('#sel_all').click(function(){
        $('.del_box input').prop('checked', $(this).prop("checked"));
    });

    //Loading shield for submit buttons
    $('.shield').hide();
    
    $('input[type=submit], body.shares_detail input[type=radio]').click(function(e) {
        e.preventDefault();
        $('body').css({
            'position' : 'relative',
            'z-index' : '1',
        });
        $('.shield').not('.reboot-message-wrapper').css({
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

function csrfSafeMethod(method) {
    // these HTTP methods do not require CSRF protection
    return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
}

$.ajaxSetup({
    beforeSend: function(xhr, settings) {
        if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
            xhr.setRequestHeader("X-CSRFToken", csrftoken);
        }
    }
});
});

console.log("Console.js Loaded");
