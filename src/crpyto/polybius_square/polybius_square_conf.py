from abc import ABC

class PolybiusSquareConfig(ABC):
    def __init__(self, table:list, width:int, height:int):
        self.table = table
        self.max_width = width
        self.max_height = height

        
    def refactor_key(self, key: str) -> list: 
        """
        this function will refactor the key to remove duplicates
        """
        new = []
        len_key = len(key)
        for i in range(len_key):
            if key[i] not in new:
                new.append(key[i])
        return new, len_key
    
    def refactor_data(self, data: str) -> list:
        return list(data)
    
    def make_table(self, key: str) -> str:
        key, _ = self.refactor_key(key)
        for x in key:
            self.table.remove(x)

        self.table = key + self.table
    

class DefaultPolybiusSquareConfig(PolybiusSquareConfig):
    '''this class is the default configuration for the PolybiusSquare cipher using only uppercase'''
    def __init__(self):
          self.table = [
                'A', 'B', 'C', 'D', 'E', 
                'F', 'G', 'H', 'I', 'K', 
                'L', 'M', 'N', 'O', 'P', 
                'Q', 'R', 'S', 'T', 'U', 
                'V', 'W', 'X', 'Y', 'Z'
          ]
          self.max_width = 5
          self.max_height = 5
          
    
    def refactor_key(self, key: str) -> list: 
        """
        this function will refactor the key to remove duplicates
        """
        key = key.upper().replace("J", "I")
        new = []
        len_key = len(key)
        for i in range(len_key):
            if key[i] not in new: new.append(key[i])
        
        return new, len_key
    
    def refactor_data(self, data: str) -> list:
        data = data.upper().replace("J", "I")
        data = ''.join([i for i in data if i.isalpha()])

        return list(data)
          
class UseNullPolybiusSquareConfig(PolybiusSquareConfig):
    def __init__(self):
        self.table = [
            '\x00', '\t', '\n', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',',
            '-', '.', '/', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<',
            '=', '>', '?', '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
            'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[', '\\',
            ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l',
            'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|',
            '}', '~', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '®', '¯',
            '°', '±', '²', '³', '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿',
            'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï',
            'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß',
            'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï',
            'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ'
        ]
        self.max_width = 16
        self.max_height = 12

            
            
class NoNullPolybiusSquareConfig(PolybiusSquareConfig):
    def __init__(self):
        self.table = [
            '\n', ' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1',
            '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D',
            'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
            'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
            'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}',
            '~', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '®', '¯', '°', '±', '²', '³',
            '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿', 'À', 'Á', 'Â', 'Ã', 'Ä', 'Å', 'Æ',
            'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 'Ö', '×', 'Ø', 'Ù',
            'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç', 'è', 'é', 'ê', 'ë', 'ì',
            'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù', 'ú', 'û', 'ü', 'ý', 'þ', 'ÿ',
        ]
        self.max_width = 19
        self.max_height = 10
