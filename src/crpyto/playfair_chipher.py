'''
this function is an inhanced version of the playfair cipher
there are some problems in the original playfair cipher like :
    - if the text contain the letter "j" it will be replaced with "i"
    - does not support numbers and special characters and Upper case letters
    - there is a confusion between "i" and "j"
    
this version will solve these problems and add some features like :
    - support numbers and special characters and Upper case letters
    - support any key
    
    
my base table is like:
ss= ['\x00',' ', '!', '"', '#', '$', '%', '&', "'", '(', ')', '*', '+', ',', '-', '.', '/', '0', '1', 
'2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?', '@', 'A', 'B', 'C', 'D', 
'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 
'X', 'Y', 'Z', '[', '\\', ']', '^', '_', '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 
'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', 
'~', '¡', '¢', '£', '¤', '¥', '¦', '§', '¨', '©', 'ª', '«', '¬', '®', '¯', '°', '±', 
'²', '³', '´', 'µ', '¶', '·', '¸', '¹', 'º', '»', '¼', '½', '¾', '¿', 'À', 'Á', 'Â', 'Ã', 
'Ä', 'Å', 'Æ', 'Ç', 'È', 'É', 'Ê', 'Ë', 'Ì', 'Í', 'Î', 'Ï', 'Ð', 'Ñ', 'Ò', 'Ó', 'Ô', 'Õ', 
'Ö', '×', 'Ø', 'Ù', 'Ú', 'Û', 'Ü', 'Ý', 'Þ', 'ß', 'à', 'á', 'â', 'ã', 'ä', 'å', 'æ', 'ç', 
'è', 'é', 'ê', 'ë', 'ì', 'í', 'î', 'ï', 'ð', 'ñ', 'ò', 'ó', 'ô', 'õ', 'ö', '÷', 'ø', 'ù', 
'ú', 'û', 'ü', 'ý', 'þ','\n']

- if the text is impair i will put '\x00' at the end

TODO : add unicode support (arabic, chinese, ...)

'''

from .base import SymetricCrypto
import string

class PlayfairCipher(SymetricCrypto):
    
    def __init__(self, key:str):
        super().__init__(key)
        self.table = self.make_table(key)
    
    def encrypt(self, data:str) -> str:
        pass
    
    def decrypt(self, data:str) -> str:
        pass
    
    def make_table(self, key:str) -> str:
        pass
         
      
        
        
        