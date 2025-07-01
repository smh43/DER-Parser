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

    Types restants: BIT STRING, OBJECT IDENTIFIER, UTF8STRING, SET, PrintableString, IA5String, UTCTIME, GeneralizedTime

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
            out, index = self.readBlock(index)
            asn.append(out)
            
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

    def readBlock(self, indexType: int, indent=False) -> list[str, int]: #retourne la valeur de l'élément, et le nouvel index

        if(indexType < len(self.key)-1):
            peek = self.key[indexType+1]
        else:
            #gestion des erreurs mauvaises parce que justement tous les types ne sont pas définis
            raise(OverflowError, "Un type est défini sur le dernier octet")

        Block="\n"
        offset = 1
        
        if(self.key[indexType] == 0x30 or self.key[indexType] == 0x10): #struct
            Block +="SEQUENCE: "
            indexSequence = indexType
            taille, o = self.getLength(peek, indexType)
            offset += o #skip les octets de tailles

            indexSequence+=offset

            while(indexSequence + offset < indexType + taille):
                statement, indexSequence = self.readBlock(indexSequence, True)
                Block += statement
            return Block, indexSequence + offset
        
        elif(self.key[indexType] == 0x05 and peek == 0): #NULL
            if(indent): Block += '\n'
            Block += "NULL"
            return Block, indexType + 2
        
        elif(self.key[indexType] == 0x02): #INT

            if(indent):  Block += '\t'
            Block += "INTEGER : "

            offset = 1
            tabInt = []

            taille, o = self.getLength(peek, indexType)
            offset += o #skip les octets pour la taille

            for i in range(0, taille):

                tabInt.append(self.key[indexType + offset])
                offset+=1
  
            n = int.from_bytes(tabInt, 'big')

            Block += str(n)
            Block += '\n'
            return Block, indexType + offset
        
        elif(self.key[indexType] == 0x04): #string
            if(indent): Block +='\t'
            Block += "STRING: "

            offset = 1 #skip le type
            tabChar = []
            
            taille, o = self.getLength(peek, indexType)
            offset += o #skip les octets pour la taille

            for i in range(0, taille):
                tabChar.append(bytes(self.key[indexType + offset]).decode("ascii"))
                offset += 1

            Block = "".join(tabChar)
            Block+='\n'

            return Block, indexType + offset
        else:
            return "", indexType + 1 #type indéfini 
        









