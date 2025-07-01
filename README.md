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
