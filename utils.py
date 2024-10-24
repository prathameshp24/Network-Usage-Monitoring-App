def get_size(bytez):
    """Converts bytes to human-readable format."""
    for unit in ['', 'K', 'M', 'G', 'T']:
        if bytez < 1024:
            return f"{bytez:,.2f}{unit}B"
        bytez /= 1024
