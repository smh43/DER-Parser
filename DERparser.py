"""

PARSER DER
parser DER imcomplet, fonctionne uniquement pour les Octet string, les INT, et les sequences
DER fonctionne en encodant des blocks de données en 3 paramètres comme : 
    un tag (voir : https://letsencrypt.org/docs/a-warm-welcome-to-asn1-and-der/) / 1 octet
    sa longueur:
        si il vaut moins de 0x80, alors la longueur de la valeur sera la valeur de cet octet / 1 octet
        si il vaut plus que 0x80, cet octet indiquera alors le nombre d'octets qui indiquent la valeur (ex : 0x82 signifie que les 2 octets suivants sont la longueur) / variable
    la valeur:
        Dépend du type et de la longueur 
    
    Il y a également un type NULL, qui a une taille de 0 et qui ne fait rien

    Ce parser ordonne par indentation, pour chaque séquence une identation supplémentaire est ajouté

    Types restants:UTF8STRING, SET, UTCTIME, GeneralizedTime
    Objet Identifier est a corriger, il faut concatener les bits en un nombre en dehors du 7eme bit

    Egalement le parser n'accepte pour l'instant que le DER en bytes
"""

class DER:

    def __init__(self, key : bytes):
        if(type(key) != bytes):
            raise(TypeError, "La clé DER doit être de type byte")
        self.key = key


    def decode(self) -> str:
        index = 0
        asn = []

        while(index < len(self.key)): #index va varier car il va s'incrémenter à chaque block
            Bloc, index = self.readBlock(index)
            asn.append(Bloc)
            
        return "".join(asn)


    def getLength(self, taille : int, index : int) -> list[int, int]: #retourne longueur et offset

        debugtaille = hex(taille)
        debugLengthTaille = hex(taille & 0b01111111)

        if(taille == 0x80):
            raise(ValueError, "Erreur de taille indéfini")
        elif(taille < 0x80): return taille, 1
        else:
            tabTaille=[]
            for offsetTaille in range(0, taille & 0b01111111): 
                tabTaille.append(self.key[index + 2 + offsetTaille])
            
            return int.from_bytes(bytes(tabTaille), 'big'), (taille & 0b01111111) + 1 #retourne la taille, et l'offset de tous les octets de taille (+1 est le premier)


    def setLengthAndOffset(self, peek : int, indexType : int) -> list[int, int]: #retourne la longueur de la valeur, et l'offset à partir du type
        taille, offset = self.getLength(peek, indexType) 
        return taille, offset + 1 #skip les octets de tailles


    def readBlock(self, indexType: int, indent=False) -> list[str, int]: #retourne la valeur de l'élément, et le nouvel index

        if(indexType < len(self.key)-1):
            peek = self.key[indexType+1] #peek va regarder l'octet suivant
        else:
            #mauvaise gestion des erreurs parce que justement tous les types ne sont pas définis
            raise(OverflowError, "Un type est défini sur le dernier octet")
            
        _type = self.key[indexType]

        taille, offset = self.setLengthAndOffset(peek, indexType)

        Block="\n"
        if(indent): Block += '\t'
        
        if(_type == 0x30 or _type == 0x10): #Sequence (l'équivalent d'une struct)
            Block += "SEQUENCE: "
            indexSequence = indexType + offset

            while(indexSequence + offset < indexType + taille):
                statement, indexSequence = self.readBlock(indexSequence, True)
                Block += statement
            return Block, indexSequence + offset
        
        elif(_type == 0x11 or _type == 0x31):
            print("SET")
            return "", indexType + 1
        
        elif(_type == 0x06): #Object Identifier

            Block += "OBJECT IDENTIFIER : "

            value = self.key[indexType + offset]
            x = value // 40
            y = value % 40
            offset += 1

            tabInt = [] 
            id = [] 
            id.append(str(x))
            id.append(str(y))

            for i in range(1, taille): #1er octet déjà consumé
                octet = self.key[indexType + offset]
                tabInt.append(octet & 0b01111111)

                if(octet & 0b10000000 == 0 or i == taille - 1): #fin de l'entier
                    nb = int.from_bytes(tabInt, 'big')
                    id.append(str(nb))
                    tabInt = []

                offset += 1

            Block += ".".join(id)

            print(Block)

            return Block, indexType + offset
        
        elif(_type == 0x05 and peek == 0): #NULL

            return "NULL", indexType + 2
        
        elif(_type == 0x02): #INT

            Block += "INTEGER : "

            tabInt = []

            for i in range(0, taille):
                tabInt.append(self.key[indexType + offset])
                offset+=1
  
            n = int.from_bytes(tabInt, 'big')

            Block += str(n)
            Block += '\n'
            return Block, indexType + offset
        
        elif (_type == 0x03): #bit string

            Block += "BITSTRING ("

            padding = self.key[indexType + offset] #le bit string commence par un octet qui défine un padding
            offset += 1

            Block += f"padding de {padding} bits) : "

            chaine = ""
            
            for i in range(0, taille):
                    char = hex(self.key[indexType + offset])
                    offset += 1
                    chaine += char + " "

            Block += chaine.strip()

            return Block, indexType + offset
        
        elif(_type == 0x04 or _type == 0x13 or _type == 0x16): #string sur 1 octet

            match(_type):
                case 0x04:
                    Block += "OCTET STRING: "
                case 0x13:
                    Block += "PRINTABLE STRING: "
                case 0x16:
                    Block += "IA5 STRING: "

            tabChar = []

            for i in range(0, taille):
                tabChar.append(bytes(self.key[indexType + offset]).decode("ascii"))
                offset += 1

            Block = "".join(tabChar)
            Block+='\n'

            return Block, indexType + offset
        
        elif(_type == 0x12): #utf-8
            print("UTF-8")
            return "", indexType + 1
        
        elif(_type == 0x17): #UTCTime
            print("UTCTime")
            return "", indexType + 1
        
        elif(_type == 0x18): #Generalized time
            print("Generalized time")
            return "", indexType + 1

        else:
            return "", indexType + 1 #type indéfini 
        









