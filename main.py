"""
Network Monitoring Telegram Bot

Бот для мониторинга сетевых устройств с использованием гибридного сканирования (ARP + Ping).
Основные функции:
- Сканирование нескольких подсетей
- Автоматическое обнаружение устройств
- Отслеживание критических узлов
- Сохранение истории сканирований
- Уведомления об изменениях
"""

import asyncio
import logging
import os
import threading
import time
from datetime import datetime
from ipaddress import IPv4Network
from typing import Dict, List, Set

import pandas as pd
import schedule
from dotenv import load_dotenv
from pythonping import ping
from scapy.all import ARP, Ether, srp
from scapy.error import Scapy_Exception
from telegram import ReplyKeyboardMarkup, ReplyKeyboardRemove, Update
from telegram.ext import (Application, CallbackContext, CommandHandler,
                          MessageHandler, filters)

# --- КОНФИГУРАЦИЯ --- #
load_dotenv()  # Загрузка переменных окружения из .env файла

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Параметры из .env
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')  # Токен Telegram бота
NETWORKS = os.getenv('NETWORKS', '192.168.1.0/24').split(',')  # Список подсетей для сканирования
ADMIN_IDS = [int(id_) for id_ in os.getenv('ADMIN_IDS', '').split(',') if id_.isdigit()]
SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', '15'))  # Интервал сканирования в минутах
CRITICAL_TAG = os.getenv('CRITICAL_TAG', 'Critical')  # Тег для критических устройств
USE_ARP = os.getenv('USE_ARP', 'true').lower() == 'true'  # Использовать ARP-сканирование

# Пути к файлам
IGNORED_IPS_FILE = 'ignored_ips.txt'
SCAN_RESULTS_FILE = 'network_devices.xlsx'
SCAN_HISTORY_FILE = 'scan_history.xlsx'

class NetworkScanner:
    """
    Класс для управления сканированием сети и хранения результатов
    
    Attributes:
        ignored_ips (Set[str]): Множество игнорируемых IP-адресов
        last_results (pd.DataFrame): Результаты последнего сканирования
        critical_changes (List[str]): Список изменений критических узлов
    """
    
    def __init__(self):
        self.ignored_ips = self._load_ignored_ips()
        self.last_results = pd.DataFrame()
        self.critical_changes = []
    
    def _load_ignored_ips(self) -> Set[str]:
        """Загрузка игнорируемых IP из файла"""
        try:
            with open(IGNORED_IPS_FILE, 'r') as f:
                return {line.strip() for line in f if line.strip()}
        except FileNotFoundError:
            return set()

    def save_ignored_ips(self):
        """Сохранение списка игнорируемых IP в файл"""
        with open(IGNORED_IPS_FILE, 'w') as f:
            for ip in self.ignored_ips:
                f.write(f"{ip}\n")

    def arp_scan(self, network: str) -> Dict[str, Dict]:
        """
        ARP-сканирование сети с получением MAC-адресов
        
        Args:
            network (str): Подсеть для сканирования (формат '192.168.1.0/24')
            
        Returns:
            Dict[str, Dict]: Словарь с обнаруженными устройствами {IP: {данные}}
        """
        devices = {}
        try:
            if os.geteuid() != 0:
                logger.warning("ARP-сканирование требует прав root (запустите с sudo)")
                return devices

            logger.info(f"Начинаю ARP-сканирование сети {network}")
            
            # Создаем и отправляем ARP-запрос
            ans, _ = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                timeout=2,
                verbose=False
            )
            
            # Обрабатываем ответы
            for _, rcv in ans:
                ip = rcv.psrc
                devices[ip] = {
                    'IP': ip,
                    'MAC': rcv.hwsrc,
                    'Status': 'Online',
                    'Last Seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'Network': network
                }
                
            logger.info(f"Обнаружено {len(devices)} устройств в сети {network}")
        except Exception as e:
            logger.error(f"Ошибка ARP-сканирования: {e}")
        
        return devices

    async def ping_scan(self, ip: str, network: str) -> Dict:
        """
        Ping-сканирование отдельного IP с подробной информацией
        
        Args:
            ip (str): IP-адрес для проверки
            network (str): Исходная подсеть
            
        Returns:
            Dict: Информация об устройстве или None если недоступно
        """
        try:
            response = ping(ip, count=2, timeout=1, verbose=False)
            if response.success():
                return {
                    'IP': ip,
                    'MAC': None,
                    'Status': 'Online',
                    'Avg Response (ms)': response.rtt_avg_ms,
                    'Packet Loss (%)': response.packet_loss * 100,
                    'Last Seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'Network': network
                }
        except Exception as e:
            logger.error(f"Ошибка ping для {ip}: {e}")
        return None

    async def scan_network(self, network: str) -> pd.DataFrame:
        """
        Гибридное сканирование одной подсети
        
        Этапы:
        1. ARP-сканирование (если разрешено и есть права)
        2. Дополнительное ping-сканирование для пропущенных IP
        3. Объединение результатов
        """
        all_ips = {str(ip) for ip in IPv4Network(network).hosts()}
        active_devices = {}
        
        # Этап 1: ARP-сканирование
        if USE_ARP:
            arp_results = self.arp_scan(network)
            active_devices.update(arp_results)
        
        # Этап 2: Ping-сканирование для пропущенных IP
        ips_to_scan = [ip for ip in all_ips 
                      if ip not in self.ignored_ips and ip not in active_devices]
        
        if ips_to_scan:
            logger.info(f"Ping-сканирование {len(ips_to_scan)} IP в сети {network}")
            tasks = [self.ping_scan(ip, network) for ip in ips_to_scan]
            results = await asyncio.gather(*tasks)
            
            for device in filter(None, results):
                active_devices[device['IP']] = device
        
        return pd.DataFrame(active_devices.values())

    async def scan_all_networks(self) -> pd.DataFrame:
        """Сканирование всех указанных подсетей"""
        all_results = []
        
        for network in NETWORKS:
            network = network.strip()
            try:
                df = await self.scan_network(network)
                if not df.empty:
                    all_results.append(df)
            except Exception as e:
                logger.error(f"Ошибка сканирования сети {network}: {e}")
        
        return pd.concat(all_results, ignore_index=True) if all_results else pd.DataFrame()

    def check_critical_changes(self, new_results: pd.DataFrame):
        """Анализ изменений в критических узлах"""
        if self.last_results.empty:
            self.last_results = new_results
            return []
        
        critical_prev = self.last_results[self.last_results['Tags'] == CRITICAL_TAG]
        critical_new = new_results[new_results['Tags'] == CRITICAL_TAG]
        
        changes = []
        
        # Анализ изменений статуса
        merged = critical_prev.merge(critical_new, on='IP', how='outer', suffixes=('_prev', '_new'))
        
        for _, row in merged.iterrows():
            if pd.isna(row['Status_prev']):
                changes.append(f"Новый критический узел: {row['IP']}")
            elif pd.isna(row['Status_new']):
                changes.append(f"Критический узел пропал: {row['IP']}")
            elif row['Status_prev'] != row['Status_new']:
                changes.append(f"{row['IP']}: {row['Status_prev']} → {row['Status_new']}")
        
        self.last_results = new_results
        self.critical_changes = changes
        return changes

    def save_results(self, df: pd.DataFrame):
        """Сохранение результатов в Excel с дополнительной обработкой"""
        if df.empty:
            logger.warning("Нет данных для сохранения")
            return
        
        # Добавление тегов и имен из предыдущих результатов
        try:
            prev_df = pd.read_excel(SCAN_RESULTS_FILE)
            df = df.merge(
                prev_df[['IP', 'Tags', 'Device Name', 'Notes']],
                on='IP',
                how='left'
            )
        except FileNotFoundError:
            df['Tags'] = ''
            df['Device Name'] = ''
            df['Notes'] = ''
        
        # Сохранение текущих результатов
        df.to_excel(SCAN_RESULTS_FILE, index=False)
        
        # Добавление в историю
        try:
            history_df = pd.read_excel(SCAN_HISTORY_FILE)
            history_df = pd.concat([history_df, df], ignore_index=True)
        except FileNotFoundError:
            history_df = df
        
        history_df.to_excel(SCAN_HISTORY_FILE, index=False)

# Инициализация сканера
scanner = NetworkScanner()

# --- ФУНКЦИИ БОТА --- #
async def start(update: Update, context: CallbackContext):
    """Обработка команды /start"""
    user = update.effective_user
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("❌ Доступ запрещен")
        return
    
    networks = "\n".join(NETWORKS)
    keyboard = [
        ['🔄 Сканировать сети', '📊 Результаты'],
        ['🚫 Игнорируемые IP', '🏷 Теги'],
        ['⚙️ Настройки']
    ]
    
    await update.message.reply_text(
        f"🔍 Бот мониторинга сетей\n"
        f"Сканируемые подсети:\n{networks}\n"
        f"Интервал: {SCAN_INTERVAL} мин\n"
        f"Метод: {'ARP + Ping' if USE_ARP else 'Ping'}",
        reply_markup=ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    )

async def handle_scan(update: Update, context: CallbackContext):
    """Запуск сканирования сетей"""
    await update.message.reply_text("🔄 Сканирую сети...")
    
    try:
        df = await scanner.scan_all_networks()
        scanner.save_results(df)
        scanner.check_critical_changes(df)
        
        online = df[df['Status'] == 'Online']
        message = (
            f"✅ Сканирование завершено\n"
            f"Всего устройств: {len(online)}\n"
            f"Сетей: {len(NETWORKS)}\n"
            f"Файл: {SCAN_RESULTS_FILE}"
        )
        
        if scanner.critical_changes:
            message += "\n\n🔔 Изменения:\n" + "\n".join(scanner.critical_changes[:5])  # Первые 5 изменений
        
        await update.message.reply_text(message)
        
        # Отправка файла
        with open(SCAN_RESULTS_FILE, 'rb') as f:
            await update.message.reply_document(
                document=f,
                caption=f"Результаты сканирования {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
    except Exception as e:
        logger.error(f"Ошибка сканирования: {e}")
        await update.message.reply_text("❌ Ошибка сканирования")

# ... (остальные обработчики сообщений)

def start_scheduler(application):
    """Настройка периодического сканирования"""
    def run_scan():
        asyncio.run_coroutine_threadsafe(
            scheduled_scan(application),
            application.loop
        )
    
    schedule.every(SCAN_INTERVAL).minutes.do(run_scan)
    
    def scheduler_loop():
        while True:
            schedule.run_pending()
            time.sleep(1)
    
    threading.Thread(target=scheduler_loop, daemon=True).start()

async def scheduled_scan(context: CallbackContext):
    """Периодическое сканирование по расписанию"""
    logger.info("Запуск автоматического сканирования")
    try:
        df = await scanner.scan_all_networks()
        scanner.save_results(df)
        changes = scanner.check_critical_changes(df)
        
        if changes:
            message = "🔔 Изменения в сети:\n" + "\n".join(changes[:3])  # Первые 3 изменения
            for admin_id in ADMIN_IDS:
                await context.bot.send_message(admin_id, message)
    except Exception as e:
        logger.error(f"Ошибка автоматического сканирования: {e}")

def main():
    """Запуск бота"""
    if not TOKEN:
        logger.error("Не указан TOKEN в .env")
        return
    
    # Проверка прав для ARP
    if USE_ARP and os.geteuid() != 0:
        logger.warning("Для ARP-сканирования запустите с sudo")
    
    app = Application.builder().token(TOKEN).build()
    
    # Регистрация обработчиков
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))
    
    # Запуск планировщика
    start_scheduler(app)
    
    logger.info(f"Бот запущен. Сканируемые сети: {NETWORKS}")
    app.run_polling()

if __name__ == '__main__':
    main()