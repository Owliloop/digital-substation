import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.neighbors import NearestNeighbors
from sklearn.cluster import KMeans
from sklearn.feature_selection import SelectKBest, chi2
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import Dense, Lambda
from tensorflow.keras.utils import to_categorical
import time


print("📘 Загрузка данных и обучение модели RBF...")

# ===================== 1. ЧТЕНИЕ ДАННЫХ =====================
file_path = 'packets1.xlsx'
all_sheets = pd.read_excel(file_path, sheet_name=None)
data = pd.concat(all_sheets.values(), ignore_index=True)

# Целевой и входные признаки
y = data['Label']
X = data.drop(columns=['Label'])

# ===================== 1.5 ПРЕОБРАЗОВАНИЕ TIMESTAMP =====================
# ИСПРАВЛЕНО: преобразуем timestamp в число
if 'timestamp' in X.columns:
    print("🕐 Преобразование timestamp в числовой формат...")
    # Преобразуем в datetime, затем в секунды
    X['timestamp'] = pd.to_datetime(X['timestamp']).astype('int64') // 10**9

# ===================== 2. ПОДГОТОВКА ПРИЗНАКОВ =====================
col_label_encoders = {}
categorical_maps = {}

for col in X.columns:
    if X[col].dtype == 'object':
        le_temp = LabelEncoder()
        X[col] = le_temp.fit_transform(X[col].astype(str))
        col_label_encoders[col] = le_temp
        categorical_maps[col] = {val: code for code, val in enumerate(le_temp.classes_)}

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X.values)

# ===================== 3. ПОДГОТОВКА ЦЕЛЕВОГО ПРИЗНАКА =====================
le = LabelEncoder()
y = le.fit_transform(y)
y = to_categorical(y)
target_classes = le.classes_

# ===================== 4. ВЫБОР ПРИЗНАКОВ =====================
selector = SelectKBest(score_func=chi2)
X_new = selector.fit_transform(X_scaled, y)
selected_features = X.columns[selector.get_support()]
selected_idx = selector.get_support(indices=True)
print("✅ Отобранные признаки:", list(selected_features))

# ===================== 5. РАЗДЕЛЕНИЕ =====================
X_train, X_test, y_train, y_test = train_test_split(
    X_new, y, test_size=0.3, random_state=42, stratify=y
)

# ===================== 6. НАСТРОЙКА RBF =====================
num_centers = 10
kmeans = KMeans(n_clusters=num_centers, random_state=42)
kmeans.fit(X_train)
centers = kmeans.cluster_centers_

nearest_neighbors = NearestNeighbors(n_neighbors=5).fit(centers)
distances, _ = nearest_neighbors.kneighbors(centers)
betas = 1 / (2 * np.mean(distances[:, 1:], axis=1) ** 2)

def rbf_layer(x, centers, betas):
    return tf.exp(-betas * tf.reduce_sum(tf.square(tf.expand_dims(x, axis=1) - centers), axis=-1))

class RBFNet(Model):
    def __init__(self, num_classes, centers, betas):
        super(RBFNet, self).__init__()
        self.rbf_layer = Lambda(lambda x: rbf_layer(x, centers, betas))
        self.out_layer = Dense(num_classes, activation='softmax')
    def call(self, inputs):
        x = self.rbf_layer(inputs)
        return self.out_layer(x)

model = RBFNet(num_classes=y.shape[1], centers=centers, betas=betas)
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# ===================== 7. ОБУЧЕНИЕ =====================
history = model.fit(X_train, y_train, epochs=10, batch_size=16, validation_split=0.2, verbose=1)
test_loss, test_accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f"🎯 Accuracy on test set: {test_accuracy:.4f}")

# ===================== 8. ОПТИМИЗИРОВАННОЕ ПРЕДСКАЗАНИЕ =====================

@tf.function
def model_predict_tf(x):
    """Предварительно трассированная TF-функция (ускоряет вызов model.predict)."""
    return model(x, training=False)

def preprocess_numpy_row(values_dict):
    """
    Преобразует словарь {колонка: значение} в numpy-массив нужной формы.
    """
    n = len(X.columns)
    arr = np.zeros((1, n), dtype=float)
    for i, col in enumerate(X.columns):
        v = values_dict.get(col, 0)
        if col in categorical_maps:
            arr[0, i] = categorical_maps[col].get(str(v), 0)
        else:
            arr[0, i] = float(v)
    return arr

def predict_fast(timestamp, cb, alarm, current, voltage, power, log_time=True):
    """
    Ускоренное предсказание (numpy + tf.function).
    Возвращает строковую метку класса.
    Если log_time=True — выводит время выполнения.
    """
    start_time = time.perf_counter()

    # преобразуем в число
    if isinstance(timestamp, str):
        try:
            timestamp = pd.to_datetime(timestamp).timestamp()
        except:
            timestamp = 0

    vals = {
        "timestamp": timestamp,
        "cb": cb,
        "alarm": alarm,
        "current": current,
        "voltage": voltage,
        "power": power
    }

    # numpy-предобработка
    arr_full = preprocess_numpy_row(vals)
    arr_scaled = scaler.transform(arr_full)   # нормализация
    arr_selected = arr_scaled[:, selected_idx]  # отбор признаков

    # предсказание с трассировкой
    x_tf = tf.constant(arr_selected, dtype=tf.float32)
    preds = model_predict_tf(x_tf)

    pred_idx = int(tf.argmax(preds, axis=1).numpy()[0])
    label = target_classes[pred_idx]

    end_time = time.perf_counter()
    elapsed_ms = (end_time - start_time) * 1000

    if log_time:
        #print(f"🕒 Предсказание выполнено за {elapsed_ms:.2f} мс → Label: {label}")
        pass

    return label