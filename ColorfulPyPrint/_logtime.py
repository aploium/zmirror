def logtime(is_print_date=False, timesep=':', datesep='-'):
    from time import time, localtime, strftime
    _localtime = localtime(time())
    _dateformat = '%Y' + datesep + '%m' + datesep + '%d'
    _timeformat = '%H' + timesep + '%M' + timesep + '%S'
    if is_print_date:
        return strftime(_dateformat + " " + _timeformat, _localtime)
    else:
        return strftime(_timeformat, _localtime)
