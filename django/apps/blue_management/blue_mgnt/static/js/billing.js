(function($, _, Backbone, swig){
    "use strict";
    var Templates = {};
    swig.setDefaults({
        varControls: ["<%-", "%>"],
        tagControls: ["<%", "%>"],
        cmtControls: ["<#", "#>"]
        //loader: swig.loaders.memory(_templates)
    });

    _.each($("script[type='text/x-swig-template']"), function(el) {
        var $el = $(el);
        var id = _.str.strRight($el.attr("id"), "-");
        try {
            Templates[id] = swig.compile(_.str.trim($el.html()));
        } catch (err) {
            console.debug(err);
            console.log(err.source);
            console.log(err.stack);
        }
    });

    var scrollTo = function($el) {
        $('html, body').stop().animate({
            scrollTop: $el.offset().top
        }, 500);
    };

    var $base = $("#billing-dropzone");

    var COUPON_STATES = {
        'NONE': 0,
        'CHECKING': 1,
        'SUCCESS': 2,
        'FAILURE': 3,
        'ERROR': 4
    };

    var COUPON_CACHE = {};

    var calculate_price = function(quantity, frequency, coupon) {
            var per, per_str;
            if (frequency === "monthly") {
                per = 5;
                per_str = "/month";
            } else {
                per = 60;
                per_str = "/year";
            }
            return {
                'int': (per * quantity),
                'str': (per * quantity) + per_str
            };
    };

    var BillingState = Backbone.Model.extend({
        defaults: {
            quantity: 10,
            frequency: "monthly",
            coupon: null,
            coupon_state: COUPON_STATES.NONE,
            stripe_token: null,
            stripe_type: null,
            stripe_last4: null,
            stripe_memo: null
        },
        initialize: function() {
            this.on("change:coupon", this.onPromoCodeChange, this);
        },
        onPromoCodeChange: function() {
            var coupon_code = this.get("coupon");
            if (!coupon_code) {
                this.set("coupon_state", COUPON_STATES.NONE);
                return;
            }
            this.set("coupon_state", COUPON_STATES.CHECKING);
            var xhr = $.ajax("/billing/check_coupon", {
                type: "POST",
                data: {
                    'coupon_code': coupon_code
                }
            })
            .done(function(data, status, xhr) {
                COUPON_CACHE[coupon_code] = data.success ? COUPON_STATES.SUCCESS : COUPON_STATES.FAILURE;
            })
            .fail(function(xhr, status, err) {
                COUPON_CACHE[coupon_code] = COUPON_STATES.ERROR;
            })
            .always(_.bind(function() {
                if (this.get("coupon") === coupon_code) {
                    this.set("coupon_state", COUPON_CACHE[coupon_code]);
                }
            }, this));
        }
    });
    var state = new BillingState();

    var Pager = Backbone.View.extend({
        initialize: function() {
            this.pages = {};
        },
        addPage: function(name, view) {
            this.pages[name] = view;
            view.render();
            view.$el.hide();
            this.$el.append(view.$el);
        },
        switchTo: function(name) {
            alerter.clear();
            var matched = false;
            _.each(this.pages, function(view, key) {
                if (key === name) {
                    view.$el.show();
                    this.trigger("switchTo", name);
                    matched = true;
                } else {
                    view.$el.hide();
                }
            }, this);
            if (!matched) {
                console.log("No page " + name);
            }
        }
    });

    var View = Backbone.View.extend({
        template: null,
        modelTriggers: ["all"],
        initialize: function(options) {
            this.model = null;
            if (options && options.model) {
                this.model = options.model;
                _.each(this.modelTriggers, function(spec) {
                    this.listenTo(this.model, spec, this.render);
                }, this);
            }
            if (options && options.template) {
                this.template = options.template;
            }
            if (_.isNull(Templates[this.template])) {
                console.error("Warning, template doesn't exist: " + this.template);
            }
            _.result(this, "onInitialize");
        },
        render: function() {
            var ctx = this.getContext();
            this.$el.html(Templates[this.template](ctx));
            this.$el.addClass(this.template);
            _.result(this, "onRender");
        },
        getContext: function() {
            return {};
        }
    });

    var AlertView = View.extend({
        template: "billing-alert",
        clear: function() {
            this.$("div").hide().attr("class", "");
            this.$("p").text("");
        },
        alert: function(msg) {
            this.$("p").text(msg);
            this.$("div").show().attr("class", "error-alert");
            scrollTo(this.$el);
        }
    });

    var Nav = Backbone.View.extend({
        activeClass: "billing-nav-active",
        initialize: function() {
            this.$el.html(Templates["billing-nav"]());
            this.$el.addClass("billing-nav");
        },
        render: function(page) {
            if (page) {
                this.$("li").removeClass(this.activeClass);
                this.$(".billing-nav-" + page).addClass(this.activeClass);
            }
        }
    });

    var pager = new Pager();
    pager.render();
    pager.addPage("plan", new View({template: "billing-plan"}));
    pager.addPage("payment", new View({template: "billing-payment"}));
    pager.addPage("summary", new View({template: "billing-summary"}));
    pager.addPage("loading", new View({template: "billing-loading"}));
    pager.addPage("success", new View({template: "billing-success"}));

    var PlanFrequencyView = View.extend({
        template: "billing-select-frequency",
        events: {
            "click li": "onFrequencySelect"
        },
        onFrequencySelect: function(evt) {
            evt.preventDefault();
            var $el = $(evt.currentTarget);
            this.model.set("frequency", $el.attr("data-frequency"));
        },
        getContext: function() {
            return {};
        },
        onRender: function() {
            var frequency = this.model.get("frequency");
            this.$("." + frequency + "-frequency").addClass("active");
        }
    });

    var PlanSizeView = View.extend({
        template: "billing-select-size",
        events: {
            "click li": "onPlanSelect",
            "click #show_more": "onClickShowMore"
        },
        onInitialize: function() {
            this.show_more = false;
        },
        onPlanSelect: function(evt) {
            evt.preventDefault();
            var $el = $(evt.currentTarget);
            var quantity = parseInt($el.attr("data-quantity"), 10);
            this.model.set("quantity", quantity);
        },
        onClickShowMore: function(evt) {
            evt.preventDefault();
            this.show_more = true;
            this.render();
        },
        getContext: function() {
            var plans = [];
            var frequency = this.model.get("frequency");
            var curr_quantity = this.model.get("quantity");
            var n = 0;
            var quantity_selected = false;
            for (var i = 10; i <= 200; i += 5) {
                if (!this.show_more && n >= 12) {
                    break;
                }
                if (SMB.total_users <= i) {
                    plans.push({
                        quantity: i,
                        price: calculate_price(i, frequency),
                        active: (i === curr_quantity)
                    });
                    if (i === curr_quantity) {
                        quantity_selected = true;
                    }
                    n += 1;
                }
            }
            if (!quantity_selected) {
                var plan = plans[0];
                plans[0].active = true;
                this.model.set("quantity", plan.quantity, {"silent": true});
            }
            return {
                plans: plans,
                show_more: this.show_more
            };
        }
    });

    var CouponView = View.extend({
        template: "billing-select-coupon",
        events: {
            "submit form": "onFormSubmit"
        },
        onRender: function() {
            this.$("input").val(this.model.get("coupon"));
        },
        onFormSubmit: function(evt) {
            evt.preventDefault();
            alerter.clear();
            var val = this.$("input").val();
            this.model.set("coupon", val);
        },
        isValid: function() {
            var coupon_state = this.model.get("coupon_state");
            return (coupon_state === COUPON_STATES.NONE || coupon_state === COUPON_STATES.SUCCESS);
        },
        getContext: function() {
            var msg, msg_class;
            var coupon_state = this.model.get("coupon_state");
            switch (coupon_state) {
                case COUPON_STATES.NONE:
                    break;
                case COUPON_STATES.CHECKING:
                    msg = "<img src='/static/blue_mgnt/img/loader.gif'> Validating..."
                    msg_class = "progress";
                    break;
                case COUPON_STATES.SUCCESS:
                    msg = "Code accepted!";
                    msg_class = "success";
                    break;
                case COUPON_STATES.FAILURE:
                    msg = "Invalid code";
                    msg_class = "error";
                    break;
                case COUPON_STATES.ERROR:
                    msg = "An error occured";
                    msg_class = "error";
                    break;
            }
            return {
                msg: msg,
                msg_class: msg_class
            };
        }
    });

    var CostPreviewView = View.extend({
        template: "billing-cost-preview",
        getContext: function() {
            var frequency = this.model.get("frequency");
            var quantity = this.model.get("quantity");
            return {
                price: calculate_price(quantity, frequency)
            };
        },
    });

    var NextView = View.extend({
        template: "billing-next",
        events: {
            "click button": "onClickNext"
        },
        onClickNext: function(evt) {
            evt.preventDefault();
            this.trigger("onClickNext");
        }
    });

    var BillingOverviewView = View.extend({
        template: "billing-overview",
        events: {
            "click .edit": "onClickEdit",
            "click .billing-next button": "onFormSubmit",
        },
        onFormSubmit: function(evt) {
            evt.preventDefault();
            alerter.clear();
            var stripe_token = this.model.get("stripe_token");
            if (stripe_token) {
                pager.switchTo("loading");
                var xhr = $.ajax("/billing/create_subscription", {
                    type: "POST",
                    data: {
                        'coupon': this.model.get("coupon"),
                        'quantity': this.model.get("quantity"),
                        'frequency': this.model.get("frequency"),
                        'stripe_memo': this.model.get("stripe_memo"),
                        'stripe_token': stripe_token
                    }
                })
                .done(function(data, status, xhr) {
                    pager.switchTo("success");
                    alerter.clear();
                    nav.$el.hide();
                })
                .fail(function(data, status, xhr) {
                    pager.switchTo("summary");
                    alerter.alert("There was an error contacting the server. Please try again later.");
                });
            }
        },
        onClickEdit: function(evt) {
            evt.preventDefault();
            var $el = $(evt.currentTarget);
            var t = $el.attr("data-target");
            pager.switchTo(t);
        },
        getContext: function() {
            var frequency = this.model.get("frequency");
            var quantity = this.model.get("quantity");
            return {
                quantity: quantity,
                frequency: frequency,
                cc_last4: this.model.get("stripe_last4"),
                cc_type: this.model.get("stripe_type"),
                cc_memo: this.model.get("stripe_memo"),
                price: calculate_price(quantity, frequency)
            };
        }
    });

    var StripePaymentView = View.extend({
        template: "billing-stripe-payment",
        events: {
            "click .billing-next button": "onFormSubmit",
            "submit form": "onFormSubmit"
        },
        onFormSubmit: function(evt) {
            evt.preventDefault();
            alerter.clear();
            this.model.set({
                stripe_token: null,
                stripe_last4: null,
                stripe_type: null,
                stripe_memo: null
            });
            var name = this.$name.val();
            var cc = this.$cc.val();
            var csv = this.$csv.val();
            var exp_month = this.$exp_month.val();
            var exp_year = this.$exp_year.val();
            var tests = [this.checkCC(), this.checkCSV(), this.checkName(), this.checkExpiry()];
            if (_.all(tests)) {
                Stripe.card.createToken({
                    name: name,
                    number: cc,
                    cvc: csv,
                    exp_month: exp_month,
                    exp_year: exp_year
                }, _.bind(this.onStripeResponse, this));
            }
        },
        onStripeResponse: function(status, data) {
            if (status === 200 && data.card) {
                this.model.set({
                    stripe_token: data.id,
                    stripe_last4: data.card.last4,
                    stripe_type: data.card.type,
                    stripe_memo: this.$memo.val()
                });
                pager.switchTo("summary");
            } else {
                console.log(data);
            }
        },
        clearMessage: function($child) {
            var $el = $child.closest("div").find("div");
            $el.attr("class", "");
            $el.find("p").text("");
        },
        showCCType: function($child, type) {
            if (type) {
                type = type.toLowerCase();
            }
            var $el = $("div", $child.closest("div"));
            var $p = $("p", $el);
            $el.attr("class", "");
            $p.html(Templates["billing-cc-type"]());
            if (type) {
                $("li[data-value=" + type + "]").addClass("active");
            }
        },
        setMessage: function($child, msg_class, msg) {
            var $el = $child.closest("div").find("div");
            if (msg_class) {
                $el.attr("class", "alert alert-" + msg_class);
            } else {
                $el.attr("class", "");
            }
            $el.find("p").html(msg);
            $el.stop().hide().fadeIn();
        },
        checkName: function() {
            var val = this.$name.val();
            var valid = false;
            if (val) {
                valid = true;
            }
            if (valid) {
                this.clearMessage(this.$name);
            } else {
                this.setMessage(this.$name, "error", "Required field");
            }
            return valid;
        },
        checkCC: function() {
            var val = this.$cc.val();
            var valid = Stripe.card.validateCardNumber(val);
            var type = null;
            if (valid) {
                type = Stripe.card.cardType(val);
                this.showCCType(this.$cc, type);
            } else {
                this.setMessage(this.$cc, "error", "Invalid Card Number");
            }
            return valid;
        },
        checkCSV: function() {
            var val = this.$csv.val();
            var valid = Stripe.card.validateCVC(val);
            if (valid) {
                //this.setMessage(this.$csv, "success", "<i class='ss-icon'>&#x2713;</i>");
                this.clearMessage(this.$csv);
            } else {
                this.setMessage(this.$csv, "error", "Invalid CVC");
            }
            return valid;
        },
        checkExpiry: function() {
            var mon = this.$exp_month.val();
            var year = this.$exp_year.val();
            var valid = Stripe.card.validateExpiry(mon, year);
            if (valid) {
                this.clearMessage(this.$exp_month);
            } else {
                this.setMessage(this.$exp_month, "error", "Invalid Expiration");
            }
            return valid;
        },
        initialize: function() {
            this.$el.html(Templates[this.template]());
            this.$el.addClass(this.template);
            var addValidateHook = function($el, cb) {
            };
            this.$name = this.$("#stripe_name");
            this.$cc = this.$("#stripe_cc");
            this.$csv = this.$("#stripe_csv");
            this.$exp_month = this.$("#stripe_exp_month");
            this.$exp_year = this.$("#stripe_exp_year");
            this.$memo = this.$("#stripe_memo");

            this.$cc.payment("formatCardNumber");
            this.$csv.payment("formatCardCVC");
            this.$cc.on("focus", _.bind(function(evt) {
                var val = this.$cc.val();
                var valid = Stripe.card.validateCardNumber(val);
                var type = null;
                if (valid) {
                    type = Stripe.card.cardType(val);
                }
                this.showCCType(this.$cc, type);
            }, this));
            this.$csv.on("focus", _.bind(function(evt) {
                this.clearMessage(this.$csv);
            }, this));
            this.$name.on("focus", _.bind(function(evt) {
                this.clearMessage(this.$name);
            }, this));
            this.$cc.on("change blur", _.bind(this.checkCC, this));
            this.$csv.on("change blur", _.bind(this.checkCSV, this));
            this.$name.on("change blur", _.bind(this.checkName, this));
            this.$exp_month.on("change blur", _.bind(this.checkExpiry, this));
            this.$exp_year.on("change blur", _.bind(this.checkExpiry, this));
            this.showCCType(this.$cc);
        },
        render: function(page) {
            var now = new Date();
            this.$exp_month.val(now.getMonth() + 1);
            this.$exp_year.val(now.getFullYear());
        }
    });

    var plansizeview = new PlanSizeView({model:state});
    var couponview = new CouponView({model:state});
    var planfrequencyview = new PlanFrequencyView({model:state});
    var costpreview = new CostPreviewView({model:state});
    var nextview = new NextView({model:state});
    plansizeview.render();
    couponview.render();
    planfrequencyview.render();
    costpreview.render();
    nextview.render();

    var stripepaymentview = new StripePaymentView({model: state});
    stripepaymentview.render();

    var billingoverviewview = new BillingOverviewView({model: state});
    billingoverviewview.render();

    var nav = new Nav();
    nav.render();
    nav.listenTo(pager, "switchTo", function(v) {
        this.render(v);
    });

    var alerter = new AlertView();
    alerter.render();

    $base.append(nav.$el);
    $base.append(alerter.$el);
    $base.append(pager.$el);
    pager.pages.plan.$el.append(plansizeview.$el);
    pager.pages.plan.$el.append(planfrequencyview.$el);
    pager.pages.plan.$el.append(couponview.$el);
    pager.pages.plan.$el.append(costpreview.$el);
    pager.pages.plan.$el.append(nextview.$el);

    pager.pages.payment.$el.append(stripepaymentview.$el);

    pager.pages.summary.$el.append(billingoverviewview.$el);

    nav.listenTo(pager, "switchTo", function(page) {
        switch(page) {
            case "success":
                $(".page-header").hide();
            case "loading":
                this.$el.hide();
                break;
            default:
                this.$el.show();
                break;
        }
    });
    pager.listenTo(nextview, "onClickNext", function(){
        if (couponview.isValid()) {
            this.switchTo("payment");
            scrollTo(pager.$el);
        } else {
            alerter.alert("Please enter a valid coupon");
        }
    });
    pager.switchTo("plan");

}(jQuery, _, Backbone, swig));
