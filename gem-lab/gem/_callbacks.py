import weakref


def weak_callback(method):
    owner_ref = weakref.ref(method.__self__)
    function = method.__func__

    def invoke(*args, **kwargs):
        owner = owner_ref()
        if owner is not None:
            return function(owner, *args, **kwargs)
        return None

    return invoke
