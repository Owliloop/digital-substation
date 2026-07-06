import numpy as np
import time
import random

states = {  # Словарь состояний: действий
    0: 1,   # Игнорирование
    1: 1,
    2: 1,
    3: 1,
    4: 1,
    5: 2,   # Блокировка
    6: 3,   # Перенаправление
    7: 3,
    8: 3
}
states_words = ["Игнорирование", "Блокировка", "Перенаправление"]

encouragement = {   # Словарь переходов-поощрений
    0: 1,
    1: 2,
    2: 3,
    3: 4,
    4: 4,
    5: 0,
    6: 0,
    7: 0,
    8: 0
}

# Глобальный словарь для хранения времени начала инцидентов для каждого cb
incident_start_times = {}

def remove_subscription(cb_name: str, subscribed_rzas, lock):
    """Удаляет подписчика из списка subscribed_rzas."""
   
    with lock:
        # Проверка наличия подписчика в списке
        if cb_name in subscribed_rzas:
            # Удаление подписчика
            subscribed_rzas.remove(cb_name)
            print(f"[SUBS] removed={cb_name}")
            return subscribed_rzas
        else:
            print(f"[SUBS] {cb_name} not in subscribed_rzas")
            return subscribed_rzas


def add_subscription(subscribed_rzas, potential_subscribed_rzas, lock, troubles):
    """Добавляет случайного подписчика из списка potential_subscribed_rzas."""
    
    with lock:
        # Проверка наличия потенциальных подписчиков
        if not potential_subscribed_rzas:
            print("[SUBS] no potential subscribers available")
            return subscribed_rzas, potential_subscribed_rzas, troubles
        
        # Выбор случайного подписчика и его добавление
        new_cb = random.choice(potential_subscribed_rzas)
        potential_subscribed_rzas.remove(new_cb)
        subscribed_rzas.append(new_cb)
        print(f"[SUBS] added={new_cb}")
        return subscribed_rzas, potential_subscribed_rzas, troubles



def Apply_Penalty(matrix, i, j):
    """
    Функция штрафа
    :param matrix: матрица вероятностного перехода
    :param i: предыдущее состояние
    :param j: текущее состояние
    :return: matrix
    """
    current_val = matrix[i, j]

    # Определение величины штрафа и обновление значения в ячейке [i, j]
    delta = 0
    if 1 >= current_val > 0.7:
        delta = 0.2
    elif 0.7 >= current_val > 0.4:
        delta = 0.15
    elif 0.4 >= current_val > 0.1:
        delta = 0.1
    elif 0.1 >= current_val > 0:
        delta = current_val / 2

    matrix[i, j] = current_val - delta

    # Нахождение индексов других достижимых состояний в строке i, исключая элемент j
    indices = [k for k, value in enumerate(matrix[i]) if k != j and value != -1]

    # Если такие состояния есть, распределяем штраф равномерно
    if indices:
        addition = delta / len(indices)
        for k in indices:
            matrix[i, k] += addition
    else:
        matrix[i, j] += delta

    return matrix

def Apply_Reward(matrix, i, j):
    """
    Функция поощрения
    :param matrix: матрица вероятностного перехода
    :param i: предыдущее состояние
    :param j: текущее состояние
    :return: обновлённая матрица
    """
    # Определение индексов других состояний в строке i с положительными значениями
    other_indices = [k for k, value in enumerate(matrix[i]) if k != j and value > 0]

    total_delta = 0  # Сумма штрафов, которую добавим к matrix[i, j]

    for k in other_indices:
        val = matrix[i, k]

        # Определяем штраф по тем же правилам, что и в Apply_Penalty
        if 1 >= val > 0.11:
            delta = 0.1
        elif 0.11 >= val > 0:
            delta = val / 2
        # else:
        #     delta = 0

        if matrix[i, k] > 0:
            matrix[i, k] -= delta  # Применяем штраф
        total_delta += delta  # Добавляем штраф в общую сумму

    # Добавляем накопленный штраф к целевому элементу
    matrix[i, j] += total_delta

    return matrix

def Matrix_Filling():
    matrix = np.full((9, 9), -1, dtype=float)

    for i in range(1, 5):
        matrix[i][i - 1] = 1
        for j in range(0, i - 1):
            matrix[i][j] = 0

    matrix[0][6] = matrix[5][0] = matrix[6][5] = matrix[7][6] = matrix[8][6] = 0
    matrix[6][0] = matrix[6][7] = 0.5
    matrix[0][5] = matrix[5][6] = matrix[7][8] = matrix[8][7] = 1

    return matrix

def  Next_State(matrix, i):
    """
    Выбирает следующее состояние j на основе вероятностей из строки i.

    :param matrix: np.array, матрица переходных вероятностей
    :param i: int, текущее состояние
    :return: int, следующее состояние j
    """
    row = matrix[i]  # Берем строку i
    reachable = row >= 0  # Достижимые состояния (где значение не -1)

    probabilities = np.where(reachable, row, 0)  # Оставляем только допустимые вероятности
    probabilities /= probabilities.sum()  # Нормализация

    return np.random.choice(len(matrix), p=probabilities)  # Выбор состояния

def record_incident_start(cb, start_time):
    """Записывает время начала инцидента для cb"""
    global incident_start_times
    incident_start_times[cb] = start_time
    print(f"[INCIDENT] Начало инцидента для {cb} в {time.strftime('%Y-%m-%d %H:%M:%S')}")

def record_incident_end(cb, start_time):
    """Записывает время окончания инцидента для cb и выводит статистику"""
    global incident_start_times
    end_time = time.time()
    incident_duration = end_time - start_time
    
    if cb in incident_start_times:
        total_incident_duration = end_time - incident_start_times[cb]
        print(f"════════════════════════════════════════")
        print(f"АТАКА ПРЕДОТВРАЩЕНА")
        print(f"Статистика инцидента для {cb}:")
        print(f"   • Текущее действие выполнено за: {incident_duration:.5f} с")
        print(f"   • Общее время инцидента: {total_incident_duration:.2f} с")
        print(f"   • Начало: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(incident_start_times[cb]))}")
        print(f"   • Окончание: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(end_time))}")
        print(f"════════════════════════════════════════")
        # Удаляем запись об инциденте
        del incident_start_times[cb]
    else:
        print(f"Атака предотвращена за {incident_duration:.2f} с")

def Attack(matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time):
    """
    Симуляция атаки
    :param matrix: np.array, матрица переходных вероятностей
    :param state: начальное состояние
    :return: matrix, state
    """
    # Отрисовка
    current_time = time.time()
    last_state = state
    state = Next_State(matrix, state)
    
    print(f"[AUTOMATION] Действие - {states_words[states[state] - 1]}--{state}")
    match states[state]:
        case 1:
            pass
        case 2:
            subscribed_rzas = remove_subscription(cb, subscribed_rzas, lock)
        case 3:
            subscribed_rzas, potential_subscribed_rzas, troubles = add_subscription(subscribed_rzas, potential_subscribed_rzas, lock, troubles)
            with lock:
                if (cb in troubles) and (cb not in subscribed_rzas):
                    troubles.remove(cb)
            # Записываем окончание инцидента
            record_incident_end(cb, start_time)
            
            last_state = state
            state = 0
    
    
    return matrix, state, last_state, subscribed_rzas, potential_subscribed_rzas, troubles
#измененнная логика работы того, что происходит при атаке
def Attack_plus(matrix, state, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time):

    if not (potential_subscribed_rzas is None):
        Attack(matrix, 6, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time) 
    else: 
        Attack(matrix, 0, cb, subscribed_rzas, potential_subscribed_rzas, lock, troubles, start_time) 