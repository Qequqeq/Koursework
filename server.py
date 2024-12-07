import random
from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
from RSA import encrypt, tower, addouble
from AES256 import ecb_decrypt


final_key = 0
app = Flask(__name__)
CORS(app)


@app.route('/generate_key', methods=['POST'])
def generate_key():
    global final_key
    data = request.get_json()
    if not data or 'publicKey' not in data:
        return jsonify({'message': 'Ошибка: неверные данные'}), 400

    e = int(data['publicKey']['e'])
    n = int(data['publicKey']['n'])

    #генерируем большое число, которое станет "основой" для симметричного ключа
    aes_key = random.randint(2 ** 200, 2 ** 210)
    print('Отправленный ключ для AES', aes_key)

    #шифруем это число с помощью открытого ключа клиента
    result = encrypt(aes_key, (e, n))
    print("Ключ после RSA", result)

    #берем от этого числа хеш-функцию, с помощью результата будем расшифровывать сообщения от клиента
    sha_256 = hashlib.sha256(str(aes_key).encode("utf-8")).hexdigest()
    print('Хеш от ключа', sha_256)

    #использую глобальную переменную, так как обработка сообщения с открытым ключом и обработка последующих сообщений разбиты на разные функции
    final_key = sha_256




    return jsonify({
        'message': 'Ключ успешно получен',
        'id': '127.0.0.1',
        'public': {
            'RSAed_key': result
        }
    })


@app.route('/send_message', methods=['POST'])
def send_message():
    global final_key

    #принимаем отправленное с помощью симметричного шифрования сообщение сообщение
    data = request.json
    encrypted_message = data.get('encryptedMessage')
    idCL = data.get('id')

    if not encrypted_message or not idCL:
        return jsonify({"status": "error", "message": "Неверные данные"}), 400

    if data is None:
        return jsonify({"status": "error", "message": "Ключ с таким ID не найден"}), 404

    print("Получено зашифрованное сообщение:", encrypted_message)

    #переводим сообщение из массива байтов в строку
    string_list = [''.join([chr(b) for b in byte_list]) for byte_list in encrypted_message]
    print(''.join(string_list))

    #расшифровываем полученную строку
    decrypted_message = ecb_decrypt(encrypted_message, final_key)

    #выводим сообщение клиента
    print("Расшифровка:", ''.join(decrypted_message))

    return jsonify(
        {"status": "success", "message": "Сообщение успешно расшифровано", "decrypted_message": decrypted_message})


if __name__ == '__main__':
    app.run(debug=True)
