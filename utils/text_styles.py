from colorama import Fore, Style


def style_highlight(message):
    return f"{Fore.LIGHTCYAN_EX}{Style.BRIGHT}{message}{Style.RESET_ALL}"


def style_success(message):
    return f"{Fore.LIGHTGREEN_EX}{Style.BRIGHT}{message}{Style.RESET_ALL}"


def style_warning(message):
    return f"{Fore.LIGHTYELLOW_EX}{Style.BRIGHT}{message}{Style.RESET_ALL}"


def style_error(message):
    return f"{Fore.LIGHTRED_EX}{Style.BRIGHT}{message}{Style.RESET_ALL}"
