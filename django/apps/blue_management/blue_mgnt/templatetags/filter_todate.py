# Django custom template filter.
# Todate takes a JSON timestamp and converts it
# to python friendly human readable time.
# Usage: {% load filter_todate %} - placed in every template you want to use the filter.
#        Then {{ <var>|todate }} where applicable, possible chaining {{ <var>|todate|date:"MDY" }}.

from django import template
import datetime

register = template.Library()

def isFloat(string):
    try:
        float(string)
    except Exception:
        return False
    return True

@register.filter
def todate(obj):
    if isFloat(obj):
        return datetime.datetime.fromtimestamp(obj)
    else:
        return obj

