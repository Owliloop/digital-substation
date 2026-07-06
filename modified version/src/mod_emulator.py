#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import yaml
import time
import threading
import struct
import random
import os
import sys

from openpyxl import Workbook, load_workbook
from collections import defaultdict
from scapy.all import sniff, sendp, Ether, Packet
from goose_gen import build_goose_packet
import tensorflow as tf
from predict_mock import predict_fast
import matrix_and_scenarios as m_s


HEARTBEAT_TIMEOUT = 2    #  секунды — если нет пакетов от cb дольше этого, считаем "падением" / атакой
WATCHER_INTERVAL = 2      # как часто проверять (сек)

lock = threading.Lock()

XLSX_FILE = 'packets.xlsx'
XLSX_HEADERS = ['timestamp', 'goCbRef', 'alarm', 'current', 'voltage', 'power']

matrix = m_s.Matrix_Filling()
state = 4
last_state = state
troubles = list()

#для запуска сразу нескольких
config_file = sys.argv[1] if len(sys.argv) > 1 else "conf.yaml"
print("CONFIG FILE =", config_file)

with open(config_file) as f:
    config = yaml.safe_load(f)



subscribed_rzas = config["subscribed_rzas"]

print("START subscribed =", subscribed_rzas)

src_mac = config['src_mac']
dst_mac = config['dst_mac']
iface = config['iface']
goCBRef = config['goCBRef']
datSet = config['datSet']
goID = config['goID']
confRev = config['confRev']
subscribed_rzas = config['subscribed_rzas']
expected_macs = {k.lower(): v.lower() for k, v in config.get('expected_macs', {}).items()} # новое
potential_subscribed_rzas = config['potential_subscribed_rzas']

# Хранилище данных последних состояний РЗА
rza_data = defaultdict(lambda: {'alarm': False,
                                'current': 0,
                                'voltage': 0,
                                'power': 0,
                                'last_seen': 0})

agg_st, agg_sq = 1, 1
evt_st, evt_sq = 1, 1

def _ensure_xlsx(path=XLSX_FILE):
    """Создание XLSX, если его нет."""
    if not os.path.exists(path):
        wb = Workbook()
        ws = wb.active
        ws.title = "data"
        ws.append(XLSX_HEADERS)
        wb.save(path)

def parse_all_data(asn1_payload: bytes):
    # Поиск от b"\xab"
    idx = asn1_payload.find(b"\xab")
    if idx < 0:
        return None
    length = asn1_payload[idx+1]
    data = asn1_payload[idx+2: idx+2+length]
    offset = 0
    if data[offset] != 0x83:
        return None
    offset += 2
    alarm = bool(data[offset])
    offset += 1
    if data[offset] != 0x85:
        return None
    length_int = data[offset+1]
    raw = data[offset+2: offset+2+length_int]
    current = struct.unpack(">i", raw[1:])[0]
    offset += 2 + length_int
    if data[offset] != 0x85:
        return None
    length_int = data[offset+1]
    raw = data[offset+2: offset+2+length_int]
    voltage = struct.unpack(">i", raw[1:])[0]
    offset += 2 + length_int
    if data[offset] != 0x85:
        return None
    length_int = data[offset+1]
    raw = data[offset+2: offset+2+length_int]
    power = struct.unpack(">i", raw[1:])[0]
    return alarm, current, voltage, power

# проверка на дос
# допустимый максимум пакетов в секунду, с учетом задержки сети = 3
rate_state = defaultdict(lambda: {'count': 0, 'window_start': 0.0})
def check_rate_limit(cb):
    now = time.time()
    with lock:
        state = rate_state[cb]
        # окно истекло — начинаем новое
        if now - state['window_start'] > 1.0:
            state['window_start'] = now
            state['count'] = 1
            return True
        state['count'] += 1
        if state['count'] > 3:
            return False
        return True

def check_mac(cb: str, pkt): #простая проверка на соответствие mac-адреса
    """Возвращает True, если MAC отправителя соответствует ожидаемому для этого goCBRef."""
    expected = expected_macs.get(cb.lower())
    if expected is None:
        print(f"[SECURITY] Нет записи о MAC для {cb} — доверенный список не содержит устройство")
        return False
    actual = pkt.src.lower()
    if actual != expected:
        print(f"[SECURITY] Подмена MAC для {cb}! ожидался {expected}, получен {actual}")
        return False
    return True

#Проверка на подмену mac-адреса
seq_tracker = defaultdict(lambda: {'st_num': None, 'sq_num': None})
def parse_header_numbers(asn1_payload: bytes):
    """Достаёт stNum и sqNum из заголовка GOOSE PDU (не из блока allData)."""
    idx_t = asn1_payload.find(b"\x84\x08")   # находим поле времени (t)
    if idx_t < 0:
        return None
    offset = idx_t + 2 + 8   # idx_t + (тег + длина времени) + 8 байт
    if asn1_payload[offset] != 0x85:         # stNum сразу после t
        return None
    st_len = asn1_payload[offset + 1]
    st_raw = asn1_payload[offset + 2: offset + 2 + st_len]
    st_num = struct.unpack(">i", st_raw[1:])[0]
    offset += 2 + st_len
    if asn1_payload[offset] != 0x86:         # sqNum сразу после stNum
        return None
    sq_len = asn1_payload[offset + 1]
    sq_raw = asn1_payload[offset + 2: offset + 2 + sq_len]
    sq_num = struct.unpack(">i", sq_raw[1:])[0]
    return st_num, sq_num

seq_strikes = defaultdict(int)

def check_sequence(cb, st_num, sq_num):
    with lock:
        prev = seq_tracker[cb]

        if prev['st_num'] is None:
            seq_tracker[cb] = {'st_num': st_num, 'sq_num': sq_num}
            seq_strikes[cb] = 0
            return True

        if st_num == prev['st_num']:
            gap = sq_num - prev['sq_num']
            ok = (1 <= gap <= 2)
        elif st_num == prev['st_num'] + 1:
            ok = (sq_num == 1)
        else:
            ok = False

        if ok:
            seq_tracker[cb] = {'st_num': st_num, 'sq_num': sq_num}
            seq_strikes[cb] = 0
            return True
        else:
            seq_strikes[cb] += 1
            print(f"[SECURITY] {cb}: нарушение последовательности (strike {seq_strikes[cb]}/2)")
            # обновляем трекер в любом случае, чтобы не застрять на устаревшем состоянии
            seq_tracker[cb] = {'st_num': st_num, 'sq_num': sq_num}
            return seq_strikes[cb] < 2
    
# проверка на невозможное изменение st_num
def check_st_num_jump(cb, st_num):
    with lock:
        prev = seq_tracker[cb]['st_num']
        if prev is None: #первый пакет запоминаем
            if st_num > 10: #если атака начилась сразу
                print(f"[SECURITY] {cb}: подозрительно большой стартовый stNum={st_num}")
                return False
            return True
        if seq_tracker[cb].get('recovering'):
            return True
        jump = st_num - prev
        if jump > 1:
            print(f"[SECURITY] {cb}: аномальный скачок stNum ({prev} -> {st_num}, скачок={jump}, лимит=1)") 
            # лимит задан с расчетом на то, вне аварийной ситуации скачок st_num
            # не превышает 1
            return False
        elif jump < 0:
            print(f"[SECURITY] {cb}: stNum откатился назад ({prev} -> {st_num})")
            return False

        return True


def goose_sniff(pkt: Packet):
    global lock, state, last_state, matrix, troubles, subscribed_rzas, potential_subscribed_rzas
    if not pkt.haslayer('GOOSE'):
        return
    if pkt.src.lower() == src_mac.lower():
        return
    raw = bytes(pkt['GOOSE'].asn1) # Данные, закодированные в байты
    print(raw.hex())
    idx = raw.find(b"\x80")
    print("idx =", idx)
    length = raw[idx+1]
    cb = raw[idx+2: idx+2+length].decode()
    if cb not in subscribed_rzas:
        print(f"[IGNORE] {cb}")
        return
    
    #print("goCBRef =", cb)
    
    #Можно посмотреть какие подписки добавлены и какой пакет от кого условно
    print("EXPECTED:", subscribed_rzas)
    print("RECEIVED:", cb)
    print("MATCH:", cb in subscribed_rzas)

    if not check_rate_limit(cb): 
        print(f"\n[SECURITY] {cb}: превышена частота пакетов\n")
        # чтобы не тратить время на парсинг и проверку данных
        with lock:
            is_in_troubles = (cb in troubles)
        if not is_in_troubles:
            with lock:
                troubles.append(cb)
                start_time = time.time()
            m_s.record_incident_start(cb, start_time)
            m_s.Attack_plus(matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time)
        return   # не тратим ресурсы на RBF/остальные проверки для флуда
    else:
        parsed = parse_all_data(raw)
        if parsed is None:
            return
        alarm, current, voltage, power = parsed
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")


        seq_ok = True
        header_nums = parse_header_numbers(raw)
        if header_nums is not None:
            st_num, sq_num = header_nums
        seq_ok = check_sequence(cb, st_num, sq_num)
        mac_ok = check_mac(cb, pkt)
        label = 1
        if not mac_ok or not seq_ok:
            label = 0
            print(f"\n[EVT] Обнаружена подмена источника для {cb} (mac_ok={mac_ok}, seq_ok={seq_ok})\n")
        elif not check_mac(cb, pkt):
            print(f"\n[EVT] MAC-spoofing обнаружен от невалидного устройства\n")
            label = 0
        elif ((current > 100 or current < 20) or (voltage < 210 or voltage > 250) or 
            (power < 4 or power > 250)): # нет проверки на alarm, тк alarm и значения тока и вольтажа независимы
            print(f"\n[EVT] Обнаружен выход за пределы измерительных возможностей прибора {cb}\n")
            label = 0
        elif abs(power - int(current*voltage/1000)) > 1 :
            print(f"\n[EVT] Обнаружена подмена данных изза некоректного расчета мощности {cb}\n")
            label = 0
        else: label = predict_fast(timestamp, cb, alarm, current, voltage, power)
    if label == 0:
        print(f"\n[EVT] Получен нелегитимный пакет от {cb}\n")
    else:
        print(f"Получен легитимный пакет от {cb}")

    
    # Обновляем last_seen и значения под lock
    with lock:
        rza_data[cb] = {
            'alarm': alarm,
            'current': current,
            'voltage': voltage,
            'power': power,
            'last_seen': time.time()
        }
        #print("RZA_DATA =", list(rza_data.keys()))


    with lock:
        is_in_troubles = (cb in troubles)

    #print("Уже проблемный?")
    if not is_in_troubles:
        #print("Нет, не проблемный")
        if label != 1:
            with lock:
                troubles.append(cb)
                start_time = time.time()
            # Записываем начало инцидента
            m_s.record_incident_start(cb, start_time)
            m_s.Attack_plus(matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time)
        elif state < 4:
            print("reward")
            #print(f"\nlast_state - {last_state} \nstate - {state}\n")
            matrix = m_s.Apply_Reward(matrix, last_state, state)
            print(f"[AUTOMATION] Действие - {m_s.states_words[m_s.states[state] - 1]}--{state}")
            last_state = state
            state += 1
            
            
            
    else:
        #print("Да, проблемный")
        if label != 1:
            print("penalti")
            matrix = m_s.Apply_Penalty(matrix, last_state, state)
            start_time = time.time()  # Время начала текущего действия
            m_s.Attack_plus(matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time)
        else:
            print("reward2")
            matrix = m_s.Apply_Reward(matrix, last_state, state)
            with lock:
                if cb in troubles:
                    troubles.remove(cb)
            state = 4
            last_state = 4
    if alarm:
        send_event(cb)

def heartbeat_watcher():
    """
    Параллельный поток — следит за rza_data['last_seen'] и если для какого-то cb
    не было пакетов дольше HEARTBEAT_TIMEOUT, считает это атакой и вызывает m_s.Attack.
    """
    global troubles, matrix, state, last_state, subscribed_rzas, potential_subscribed_rzas
    while True:
        time.sleep(WATCHER_INTERVAL)
        now = time.time()
        # Соберём список cb для обработки вне lock, чтобы не держать блокировку длительное время
        to_handle = []
        with lock:
            for cb, info in list(rza_data.items()):
                last = info.get('last_seen', 0)
                # Если last == 0 => ещё не приходил пакет от этой RZA — пропускаем
                if last == 0:
                    continue
                if (now - last) > HEARTBEAT_TIMEOUT:
                    # если уже в troubles — уже обрабатывается, иначе добавим
                    if cb not in troubles and cb in subscribed_rzas:
                        to_handle.append(cb)

        if len(to_handle) > 0:
            # Обработка найденных "пропавших" cb (вне lock, но при добавлении в troubles используем lock)
            for cb in to_handle:
                print(f"\n[WATCHER] Нет пакетов от {cb} в течение {(now - rza_data[cb]['last_seen']):.1f}с — считаем атакой\n")
                with lock:
                    troubles.append(cb)
                    start_time = time.time()
                # Записываем начало инцидента
                m_s.record_incident_start(cb, start_time)
                # вызываем Attack (m_s.Attack использует lock внутри для подписок)
                m_s.Attack_plus(matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time)
        else:
            for cb in troubles:
                if (now - rza_data[cb]['last_seen']) > HEARTBEAT_TIMEOUT:
                    with lock:
                        matrix = m_s.Apply_Penalty(matrix, last_state, state)
                        start_time = time.time()  # Время начала текущего действия
                    # вызываем Attack (m_s.Attack использует lock внутри для подписок)
                    matrix, state, last_state, subscribed_rzas, potential_subscribed_rzas, troubles = m_s.Attack(
                        matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time
                    )
        if len(troubles)>0:
            print(f"\n[TROUBLES] Проблемы с устройством/-ами: {troubles}\n")

def sleep_watcher():
    time.sleep(5)
    global troubles, matrix, state, last_state, subscribed_rzas, potential_subscribed_rzas
    mas = []
    for cb, info in list(rza_data.items()):
        mas.append(cb)
    for sub in subscribed_rzas:
        if sub not in mas:
            print(f"{sub} не запустились\n")
            with lock:
                start_time = time.time()  # Время начала текущего действия
                # вызываем Attack (m_s.Attack использует lock внутри для подписок)
            m_s.Attack_plus(matrix, state, sub, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time)
        


def periodic_aggregate():
    global agg_st, agg_sq
    while True:
        time.sleep(5)
        with lock:
            vals = [
                v
                for cb, v in rza_data.items()
                if cb in subscribed_rzas
            ]
        if not vals:
            continue
        avg_current = sum(d['current'] for d in vals) // len(vals)
        avg_voltage = sum(d['voltage'] for d in vals) // len(vals)
        avg_power   = sum(d['power']   for d in vals) // len(vals)
        all_data = [False, avg_current, avg_voltage, avg_power]
        pkt = build_goose_packet(
            src_mac, dst_mac,
            agg_st, agg_sq,
            goCBRef, datSet, goID, confRev,
            all_data
        )
        sendp(pkt, iface=iface, verbose=False)
        agg_sq += 1
        print(f"\n[AGG] Средние: I={avg_current}A, U={avg_voltage}V, P={avg_power}kW\n")

def send_event(cb_name):
    global evt_st, evt_sq
    all_data = [True, 0, 0, 0]
    pkt = build_goose_packet(
        src_mac, dst_mac,
        evt_st, evt_sq,
        goCBRef, datSet, goID + "_EVT", confRev,
        all_data
    )
    sendp(pkt, iface=iface, verbose=False)
    evt_sq += 1
    print(f"\n[EVT] Аварийное событие от {cb_name}\n")


if __name__ == '__main__':
    #Запускаем watcher и aggregator как фоновые демоны
    threading.Thread(target=sleep_watcher, daemon=True).start()
    threading.Thread(target=heartbeat_watcher, daemon=True).start()
    threading.Thread(target=periodic_aggregate, daemon=True).start() 
    # Перехватываются пакеты, приходящие на iface, обрабатываются только GOOSE; если пришёл GOOSE, вызывается goose_sniff
    sniff(iface=iface, filter="ether proto 0x88B8", prn=goose_sniff)
    print("BEFORE SNIFF =", subscribed_rzas)