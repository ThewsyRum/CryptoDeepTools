from ecpy.curves import Curve, Point

# Abrindo o arquivo "Coordinates.txt" em modo de leitura de texto
with open("Coordinates.txt", "rt") as base:
    # Lendo o conteúdo do arquivo e dividindo-o em linhas
    for line in base.read().splitlines():
        # Convertendo as coordenadas de hexadecimal para inteiro, removendo os colchetes e espaços
        Gx, Gy = map(lambda v: int(v, 16), line[1:-1].split(" , "))

        # Obtendo a curva secp256k1
        cv = Curve.get_curve('secp256k1')

        # Criando um ponto na curva com as coordenadas Gx e Gy
        P = Point(Gx, Gy, cv)

        # Definindo o valor de B como um inteiro hexadecimal
        B = 0xdac19ec586ea8aa454fd2e7090e3244cdf75a73bdb1aa970d8b0878e75df3cae

        # Calculando o ponto A multiplicando B pelo ponto P
        A = B * P

        # Abrindo o arquivo "SaveBase.txt" em modo de adição de texto para salvar o resultado
        with open("SaveBase.txt", "a") as file:
            # Escrevendo o ponto A no arquivo e adicionando uma nova linha
            file.write(str(A))
            file.write("\n")
         
