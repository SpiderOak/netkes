from datetime import datetime
import calendar
import logging

from django.http import Http404
from django.shortcuts import redirect, render_to_response
from django.forms import ModelForm
from django.template import RequestContext

from views import enterprise_required, get_billing_api
from blue_mgnt.models import InvoiceNote


LOG = logging.getLogger(__file__)


class Invoice(object):
    def __init__(self, month):
        self.month = month
        self.payments = []

    def total_in_dollars(self):
        return sum(p['payment_amount_cents'] for p in self.payments) / 100

    def last_day_of_month(self):
        year, month, day = self.month.split('-')
        year, month = int(year), int(month)
        return datetime(year, month, calendar.monthrange(year, month)[1])

    def __str__(self):
        return '{} - {}'.format(self.month, self.payments)

    def __repr__(self):
        return '{} - {}'.format(self.month, self.payments)


def group_payments_by_month(payments):
    invoices = []
    for payment in sorted(payments, key=lambda x: x['created']):
        payment['amount_in_dollars'] = payment['payment_amount_cents'] / 100
        created = datetime.fromtimestamp(payment['created'])
        payment['created'] = created
        month = '{}-{}-1'.format(created.year, created.month)
        if not invoices or invoices[-1].month != month:
            invoices.append(Invoice(month))
        invoices[-1].payments.append(payment)

    return invoices


class InvoiceNoteForm(ModelForm):
    class Meta:
        model = InvoiceNote
        fields = ['note']


def get_invoice_note():
    if InvoiceNote.objects.count():
        return InvoiceNote.objects.all()[0]


@enterprise_required
def invoice_list(request, api, account_info, config, username):
    """ Get the list of policies and assign their parent names to each policy
    """
    billing_api = get_billing_api(config)
    invoices = group_payments_by_month(billing_api.payments())
    invoice_note = get_invoice_note()
    if request.method == 'POST':
        invoice_note_form = InvoiceNoteForm(request.POST, instance=invoice_note)
        if invoice_note_form.is_valid():
            invoice_note_form.save()
            return redirect('blue_mgnt:invoice_list')
    else:
        invoice_note_form = InvoiceNoteForm(instance=invoice_note)
    return render_to_response('invoice_list.html', {
        'invoices': invoices,
        'invoice_note_form': invoice_note_form,
    }, RequestContext(request))


@enterprise_required
def invoice_detail(request, api, account_info, config, username, invoice_month):
    """ Get the list of policies and assign their parent names to each policy
    """
    billing_api = get_billing_api(config)
    invoices = group_payments_by_month(billing_api.payments())
    invoice_note = get_invoice_note()

    invoice = None
    for invoice_ in invoices:
        if invoice_.month == invoice_month:
            invoice = invoice_
    if invoice:
        return render_to_response('invoice_detail.html', {
            'invoice': invoice,
            'invoice_month': invoice_month,
            'invoice_note': invoice_note,
        })
    raise Http404('Invoice does not exist for this month')
