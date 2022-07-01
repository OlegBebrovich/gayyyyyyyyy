import requests
from main import *
from hmac import new
from json import loads
from hashlib import sha1
from base64 import b64encode
from python_shell import Shell
from python_shell.util.streaming import decode_stream

command = Shell.dmidecode('-s','system-uuid')
hwid = str(decode_stream(command.output))

version = "1.1"

def gen(data: str) -> str:
    data = data.encode("utf-8")
    return b64encode(
                    bytes.fromhex("64") + 
                    new(
                        bytes.fromhex("5377AAA667B63370C531E6FC54A13037D8CB5F83B11DFA0A3F17BA372F9963AD3B359CFE07BC83BE32B3068DFD85E7F0AC1A6E38FBC7B8ED202FD2ACE63E0D9EC35359C9B2EF35C1C2357E78123AE9E2210252FF81285328823A"),
                        data, 
                        sha1
                        ).digest()
                    ).decode("utf-8")

config = loads(open("configs.json").read())

api = config["api"]

to = 1

if config.get("key") is None: 
    to = 0
    
if to == 1:
    if config["key"] == "": 
        to = 0
    if to == 1:
        for i in config["key"]:
            if i in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890":
                pass
            else:
                to = 0
            
if to == 0:
    exit("Для работы кода требуется ВЕРНЫЙ ключ! Он должен находиться в файле configs.json в поле \"key\", " + 
          "если у вас нет этого файла или вы удалили его или там нет ключа - обратитесь к https://t.me/Verve_is_God. " + 
          "Если ключ есть, но вы видите это сообщение - ключ не верный или он истёк, обратитесь к https://t.me/Verve_is_God")
    
else:

    key_data = {
        "key": config["key"],
        "hwid": hwid,
        "version": version
    }

    data = {
        "key": config["key"],
        "hwid": hwid
    }
    
    key = requests.get(f"{api}/key", json=key_data).json()

    if key["status"] == 0:
        data["security"] = gen(data=str(data))
        valid = requests.post(f"{api}/validate", json=data).json()
        if valid["status"] == 0:
            start(hwid, config["key"])
        elif valid["status"] == 1:
            exit("Ваш ключ забанен! Обратитесь к https://t.me/Verve_is_God, если считаете что это ошибка.")
        elif valid["status"] == 2:
            exit("Срок вашего ключа истёк! Обратитесь к https://t.me/Verve_is_God, если хотите продлить подписку.")
        elif valid["status"] == 100:
            exit("Сервер обновляется. Приносим свои извинения! Попробуйте запустить скрипт через 5 минут, если ошибка снова повторится обратитесь к https://t.me/Verve_is_God")
        elif valid["status"] == 101:
            exit("Сервер изменил сигнатуру, обратитесь к https://t.me/Verve_is_God.")
        elif valid["status"] == 500:
            exit("Внутренняя ошибка сервера.")
        else:
            exit("Неизвестная ошибка, обратитесь к https://t.me/Verve_is_God")
    elif key["status"] == 1:
        exit("Ваш ключ забанен! Обратитесь к https://t.me/Verve_is_God, если считаете что это ошибка.")
    elif key["status"] == 2:
        exit("Срок вашего ключа истёк! Обратитесь к https://t.me/Verve_is_God, если хотите продлить подписку.")
    elif key["status"] == 3:
        exit("Данный ключ не существует! Обратитесь к https://t.me/Verve_is_God, если хотите купить ключ.")
    elif key["status"] == 4:
        exit(f"Версия, которую вы используете ({version}) не действительна. Обратитесь к https://t.me/Verve_is_God за новой версией.")
    elif key["status"] == 5:
        exit(f"Ваш HWID не соответсвует с записью на сервере. Обратитесь к https://t.me/Verve_is_God , если считаете что это ошибка.")
    elif key["status"] == 100:
        exit("Сервер обновляется. Приносим свои извинения! Попробуйте запустить скрипт через 5 минут, если ошибка снова повторится обратитесь к https://t.me/Verve_is_God")
    elif key["status"] == 101:
        exit("Сервер изменил сигнатуру, обратитесь к https://t.me/Verve_is_God.")
    elif key["status"] == 500:
        exit("Внутренняя ошибка сервера.")
    else:
        exit("Неизвестная ошибка, обратитесь к https://t.me/Verve_is_God")
