(function($, _, Backbone, swig){
    "use strict";
    var state;
    var pager;
    var alerter;

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

    var toCurrency = function(v) {
        // v should already be appropriately rounded to 2 decimals.
        // this method only handles string formatting
        var ret = _.str.numberFormat(v, 2);
        if (_.str.endsWith(ret, ".00")) {
            return _.str.numberFormat(v, 0);
        }
        return ret;
    };

    var trim = String.prototype.trim ? function(s) {
        return s.trim();
    } : function(s) {
        return this.replace(/^\s+|\s+$/g, '');
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
            var percent_off, cents_off;
            if (frequency === "monthly") {
                per = SMB.monthly_cost;
                per_str = "/month";
            } else {
                per = SMB.yearly_cost;
                per_str = "/year";
            }
            var cost = (per * quantity);
            var coupon = COUPON_CACHE[coupon];
            if (coupon && coupon.state === COUPON_STATES.SUCCESS) {
                if (coupon.data.percent_off) {
                        cost = Math.floor(cost * (100 - coupon.data.percent_off)) / 100;
                }
                if (coupon.data.cents_off) {
                        cost = (cost - (coupon.data.cents_off / 100));
                }
            }
            return { 
                'int': (toCurrency(cost)),
                'str': (toCurrency(cost)) + per_str
            };
    };

    var BillingState = Backbone.Model.extend({
        defaults: {
            quantity: null,
            frequency: "monthly",
            coupon: null,
            coupon_state: COUPON_STATES.NONE,
            stripe_token: null,
            stripe_type: null,
            stripe_last4: null,
            payment_method: "new",
            has_current_plan: false,
            has_cc: false
        },
        initialize: function() {
            var quantity = Math.max(10, SMB.total_users);
            this.set("quantity", quantity);
            if (SMB.current_plan_quantity && SMB.current_plan_frequency) {
                this.set("has_current_plan", true);
                this.set("frequency", SMB.current_plan_frequency.replace(/^smb_/, "")); 
                // assume that if they have a plan they have a cc on file
                this.set("has_cc", true);
                this.set("payment_method", "existing");
            }
            this.on("change:coupon", this.onPromoCodeChange, this);
        },
        onPromoCodeChange: function() {
            var coupon_code = this.get("coupon");
            if (!coupon_code) {
                this.set("coupon_state", COUPON_STATES.NONE);
                return;
            }
            this.set("coupon_state", COUPON_STATES.CHECKING);
            if (COUPON_CACHE[coupon_code]) {
                this.set("coupon_state", COUPON_CACHE[coupon_code].state);
                return;
            }
            var xhr = $.ajax("/billing/check_coupon", {
                type: "POST",
                data: {
                    'coupon_code': coupon_code
                }
            })
            .done(function(data, status, xhr) {
                if (data.valid) {
                        COUPON_CACHE[coupon_code] = {state: COUPON_STATES.SUCCESS, data: data};
                } else {
                        COUPON_CACHE[coupon_code] = {state: COUPON_STATES.FAILURE, data: null};
                }
            })
            .fail(function(xhr, status, err) {
                COUPON_CACHE[coupon_code] = {state: COUPON_STATES.ERROR, data: null};
            })
            .always(_.bind(function() {
                if (this.get("coupon") === coupon_code) {
                    this.set("coupon_state", COUPON_CACHE[coupon_code].state);
                }
            }, this));
        }
    });
    var Pager = Backbone.View.extend({
        initialize: function() {
            this.pages = {};
            this.currPage = null;
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
                    matched = true;
                } else {
                    view.$el.hide();
                }
            }, this);
            if (!matched) {
                console.log("No page " + name);
            } else {
                this.currPage = name;
                this.trigger("switchTo", name);
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

    var CouponView = View.extend({
        template: "billing-select-coupon",
        modelTriggers: ["change:coupon", "change:coupon_state"],
        events: {
            "submit form": "onFormSubmit"
        },
        onRender: function() {
            this.$("input").val(this.model.get("coupon"));
        },
        onFormSubmit: function(evt) {
            evt.preventDefault();
            alerter.clear();
            var $input = this.$("input");
            var val = $input.val();
            this.model.set("coupon", trim(val));
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
            var coupon = this.model.get("coupon");
            return {
                has_current_plan: this.model.get("has_current_plan"),
                frequency: frequency,
                quantity: quantity,
                price: calculate_price(quantity, frequency, coupon)
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
            if (this.model.get("has_cc") && this.model.get("payment_method") === "existing") {
                pager.switchTo("loading");
                var xhr = $.ajax("/billing/create_subscription", {
                    type: "POST",
                    data: {
                        'coupon': this.model.get("coupon"),
                        'frequency': this.model.get("frequency"),
                    }
                })
                .done(function(data, status, xhr) {
                    if (data.success) {
                        if (data.msg) {
                            $("#billing-success-message").text(data.msg);
                        }
                        pager.switchTo("success");
                        alerter.clear();
                        nav.$el.hide();
                    } else {
                        pager.switchTo("summary");
                        var msg = "There was an error contacting the server. Please try again later.";
                        if (data.msg) {
                           msg = data.msg;
                        }
                        alerter.alert(msg);
                    }
                })
                .fail(function(data, status, xhr) {
                    pager.switchTo("summary");
                    alerter.alert("There was an error contacting the server. Please try again later.");
                });
                return;
            }
            var stripe_token = this.model.get("stripe_token");
            if (stripe_token) {
                pager.switchTo("loading");
                var xhr = $.ajax("/billing/create_subscription", {
                    type: "POST",
                    data: {
                        'coupon': this.model.get("coupon"),
                        'frequency': this.model.get("frequency"),
                        'stripe_token': stripe_token
                    }
                })
                .done(function(data, status, xhr) {
                    if (data.success) {
                        if (data.msg) {
                            $("#billing-success-message").text(data.msg);
                        }
                        pager.switchTo("success");
                        alerter.clear();
                    } else {
                        pager.switchTo("summary");
                        var msg = "There was an error contacting the server. Please try again later.";
                        if (data.msg) {
                           msg = data.msg;
                        }
                        alerter.alert(msg);
                    }
                })
                .fail(function(data, status, xhr) {
                    pager.switchTo("summary");
                    alerter.alert("There was an error contacting the server. Please try again later.");
                });
                return;
            }
            pager.switchTo("summary");
            alerter.alert("There was an error with the form. Please try again later.");
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
            var coupon = this.model.get("coupon");
            if (this.model.get("payment_method") === "new") {
                return {
                    has_current_plan: this.model.get("has_current_plan"),
                    quantity: quantity,
                    frequency: frequency,
                    cc_last4: this.model.get("stripe_last4"),
                    cc_type: this.model.get("stripe_type"),
                    price: calculate_price(quantity, frequency, coupon)
                };
            } else {
                return {
                    has_current_plan: this.model.get("has_current_plan"),
                    quantity: quantity,
                    frequency: frequency,
                    cc_last4: SMB.last4_on_file,
                    cc_type: "Card on file",
                    price: calculate_price(quantity, frequency, coupon)
                };
            }
        }
    });

    var PaymentMethodView = View.extend({
        template: "billing-payment-method",
        events: {
            "click li": "onMethodSelect"
        },
        onMethodSelect: function(evt) {
            evt.preventDefault();
            var $el = $(evt.currentTarget);
            this.model.set("payment_method", $el.attr("data-method"));
        },
        getContext: function() {
            return {};
        },
        onRender: function() {
            var method = this.model.get("payment_method");
            this.$(".payment-" + method).addClass("active");
            if (method === 'new') {
                this.parentView.showCCForm();
            } else {
                this.parentView.showOnFileForm();
            }
        }
    });

    var StripePaymentView = View.extend({
        template: "billing-stripe-payment",
        events: {
            "click .billing-next button": "onFormSubmit",
            "submit form": "onFormSubmit"
        },
        showCCForm: function() {
            var $form = this.$('.so-form');
            $(".cc-info", $form).show();
            $(".onfile-info", $form).hide();
        },
        showOnFileForm: function() {
            var $form = this.$('.so-form');
            $(".cc-info", $form).hide();
            $(".onfile-info", $form).show();
        },
        onFormSubmit: function(evt) {
            evt.preventDefault();
            alerter.clear();
            if (this.model.get("payment_method") === "existing") {
                pager.switchTo("summary");
                return;
            }
            this.model.set({
                stripe_token: null,
                stripe_last4: null,
                stripe_type: null
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
                    stripe_type: data.card.type
                });
                pager.switchTo("summary");
            } else {
                if (data && data.error) {
                    this.setMessage(this.$cc, "error", data.error.message);
                } else {
                    console.log(data);
                }
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
                $("li[data-value]", $p).each(function(i, el) {
                  var $el = $(el);
                  $el.toggleClass("active", $el.attr("data-value") === type);
                });
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
        initialize: function(options) {
            this.options = options || {};
            this.$el.html(Templates[this.template]());
            this.$el.addClass(this.template);
            this.$name = this.$("#stripe_name");
            this.$cc = this.$("#stripe_cc");
            this.$csv = this.$("#stripe_csv");
            this.$exp_month = this.$("#stripe_exp_month");
            this.$exp_year = this.$("#stripe_exp_year");

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

            if (!this.options.force_cc_mode) {
                this.paymentMethod = new PaymentMethodView({model: this.model});
                this.paymentMethod.parentView = this;
                if (this.model.get("has_cc")) {
                    this.paymentMethod.$el.prependTo(this.$(".so-form"));
                }
            }
        },
        render: function(page) {
            var now = new Date();
            this.$exp_month.val(now.getMonth() + 1);
            this.$exp_year.val(now.getFullYear());
            if (this.paymentMethod) {
                this.paymentMethod.render();
            }
        }
    });

    var HistoryState = Backbone.Model.extend({
        pageOrder: ["plan", "payment", "summary"],
        defaults: {
            seenPage: 0
        },
        str2page: function(s) {
            var ret = _.indexOf(this.pageOrder, s);
            if (ret === -1) {
                return null;
            }
            return ret;
        },
        page2str: function(i) {
            return this.pageOrder[i];
        },
        markSeen: function(page) {
            var i = this.str2page(page);
            this.set("seenPage", Math.max(this.get("seenPage"), i));
        },
        start: function(pager) {
            this.pager = pager;
            this.listenTo(this.pager, "switchTo", this.markSeen);
            if (history.pushState) {
                this.bindHistory();
            }
        },
        bindHistory: function() {
            history.pushState(-1, null);
            history.pushState(0, null);
            window.addEventListener("popstate", _.bind(function(evt) {
                if (evt.state === 1) {
                    // nothing to do for forward
                } else if (evt.state === -1) {
                    if (this.handleBack()) {
                        history.go(-evt.state);
                    } else {
                        history.go(-2);
                    }
                }
            }, this), false);
        },
        handleBack: function() {
            var i = this.str2page(this.pager.currPage);
            if (i === 0) {
                return false;
            }
            if (i > 0) {
                var page = this.page2str(i - 1);
                this.pager.switchTo(page);
            }
            return true;
        }
    });

    window.init_billing = function() {
        state = new BillingState();
        pager = new Pager();
        pager.render();
        pager.addPage("plan", new View({template: "billing-plan"}));
        pager.addPage("payment", new View({template: "billing-payment"}));
        pager.addPage("summary", new View({template: "billing-summary"}));
        pager.addPage("loading", new View({template: "billing-loading"}));
        pager.addPage("success", new View({template: "billing-success"}));

        var couponview = new CouponView({model:state});
        var planfrequencyview = new PlanFrequencyView({model:state});
        var costpreview = new CostPreviewView({model:state});
        var nextview = new NextView({model:state});
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

        alerter = new AlertView();
        alerter.render();

        $base.append(nav.$el);
        $base.append(alerter.$el);
        $base.append(pager.$el);
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
                    nav.$el.hide();
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

        var historyState = new HistoryState();
        historyState.start(pager);
    
        pager.switchTo("plan");
    };

    window.init_update_cc = function() {
        state = new BillingState();
        state.set("payment_method", "new");
        pager = new Pager();
        pager.render();
        pager.addPage("payment", new View({template: "billing-payment"}));
        pager.addPage("summary", new View({template: "billing-summary"}));
        pager.addPage("loading", new View({template: "billing-loading"}));
        pager.addPage("success", new View({template: "update-cc-success"}));

        var costpreview = new CostPreviewView({model:state});
        var nextview = new NextView({model:state});
        costpreview.render();
        nextview.render();

        var stripepaymentview = new StripePaymentView({model: state, force_cc_mode: true});
        stripepaymentview.render();
        stripepaymentview.showCCForm();

        var billingoverviewview = new BillingOverviewView({model: state, template: "update-cc-overview"});
        billingoverviewview.render();

        alerter = new AlertView();
        alerter.render();

        $base.append(alerter.$el);
        $base.append(pager.$el);

        pager.pages.payment.$el.append(stripepaymentview.$el);
        pager.pages.summary.$el.append(billingoverviewview.$el);
        pager.switchTo("payment");
    };
}(jQuery, _, Backbone, swig));
