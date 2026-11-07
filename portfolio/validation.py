class ValidationError(ValueError):
    pass

class ConflictError(ValueError):
    pass

class NotFoundError(LookupError):
    pass
