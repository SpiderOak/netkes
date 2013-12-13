$(function() {

    //For navigation.
        
    //Position right elements
    $('.navigation').find('li').mouseover(function(){
        var right = $(this).children('.right');
        if(right.is(':visible')){
            right.css('left', -(right.innerWidth() / 1.240));
        }
    });

    //Home button Navigation
        $('.spideroak').mouseover(function() {
            $('.spideroak').fadeTo(400, 0.4, function(){
                $('#home_option').fadeIn(600);
            });
        });

        $('.spideroak').mouseleave(function(e) {
            if($('.spideroak').is(':animated')) {
                $(this).stop().fadeTo(400, 1.0);
            }
            if(e.pageX < $('#home_option').offset().left){
                $('#home_option').fadeOut(400, function(){
                    $('.spideroak').fadeTo(400, 1.0);
                });
            }
        });

        $('#home_option').find('ul').mouseleave(function() {
            $('#home_option').fadeOut('slow', function(){
                $('.spideroak').fadeTo('slow', 1.0);
            });
        });

    //End Home button Navigation

    /*$('.sub').find('li').css({'font-weight': 'normal', 'font-size': '11px'});
    
    $('.sub').find('li').bind('mouseover', function(){
       // $(this).css({'font-style': 'italic', 'text-decoration': 'underline'});
    }).mouseout(function(){ 
        $(this).css('text-transform', 'capitalize');
    });

    $('.navigation').find('li').mouseover(function() {
        $(this).addClass('on');
    }).mouseout(function(){ 
        $('.navigation').find('li').removeClass('on');
    });*/

    // Expands the titles in engineering_matters.
    if($('#business').length){
        var root = "blue_plus.png";
        var rollover = "gold_plus.png";
        $('.marker').each(function(){
            $(this).attr('src', "/static/v0.1/images/index/" + root);
            });
    } else {
        var root = "gold_plus.png";
        var rollover = "blue_plus.png";
    }

    $('.info').hide();

    $('.title').click(function(){
        
        var visible = false;
        if($(this).next('.info').hasClass('visible')){
            visible = true;
        }

        $('.info').each(function(){
            if($(this).hasClass('visible')){
                $(this).removeClass('visible').hide();
            }
        });
        
        $('.marker').each(function(){
            $(this).attr('src', "/static/v0.1/images/index/" + root);
            });


        if(!visible){
            $(this).children('img').attr('src', "/static/v0.1/images/index/" + rollover);
            $(this).next('.info').show().addClass('visible');
        }
    });
    
    // For the press page.
    $('.toggle_defs dd').hide();
    $('.toggle_defs dt a').click(function () {
        $(this).toggleClass('inverted').parent().next().toggle(200);
        return false;
    });

    // Sort for press.html
    $('.pr_click, .link_click').click(function(event) {
        var selected = $(this).attr('id');
        var target = $(event.target);
        if(target.hasClass('pr_click')) {
            var tog = $('.t');
        } else {
            var tog = $('.l');
        }

        if(! tog.hasClass(selected)){
            alert('There are currently no posts for this year.');
            if (tog.hasClass('hidden')) {
                tog.removeClass('hidden').show();
            }

        } else {
            tog.each(function() {
                if(! $(this).hasClass(selected)){
                    $(this).addClass('hidden');
                    $(this).hide();
                } else {
                    if ($(this).hasClass(selected) && $(this).hasClass('hidden')) {
                        $(this).removeClass('hidden');
                        $(this).show();
                }
                }
            });
        }
         
    });
    
});
