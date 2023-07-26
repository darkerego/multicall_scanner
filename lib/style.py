import colored


class PrettyText:
    def normal(self, data):
        print(colored.fore.LIGHT_BLUE + colored.style.BOLD + '[' + colored.fore.RED + '+'
              + colored.fore.LIGHT_BLUE + '] ' + colored.style.RESET + str(data))

    def error(self, data):
        print(
            colored.fore.RED_1 + colored.style.BOLD + '[' + colored.fore.WHITE + '!' \
            + colored.fore.RED_1 + '] '+ colored.style.RESET + str(data))

    def good(self, data):
        print(
            colored.fore.LIGHT_GREEN + colored.style.BOLD + '[' + colored.fore.MAGENTA + '~' \
            + colored.fore.LIGHT_GREEN +  '] ' + colored.style.RESET + str(data))

    def warning(self, data):
        print(colored.fore.VIOLET + colored.style.BOLD + '[' + colored.fore.VIOLET + \
              '*' + colored.fore.VIOLET + '] ' + colored.style.RESET + str(data))