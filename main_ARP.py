import asyncio
import logging
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from ipaddress import IPv4Network

import pandas as pd
import schedule
from dotenv import load_dotenv
from scapy.all import ARP, Ether, srp
from scapy.error import Scapy_Exception
from telegram import ReplyKeyboardMarkup, ReplyKeyboardRemove, Update
from telegram.ext import (Application, CallbackContext, CommandHandler,
                          MessageHandler, filters)

# Загрузка переменных окружения
load_dotenv()

# Настройка логирования
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Конфигурация из .env
TOKEN = os.getenv('TELEGRAM_BOT_TOKEN')
NETWORK = os.getenv('NETWORK', '192.168.1.0/24')

# Надежная обработка ADMIN_IDS
ADMIN_IDS = []
if os.getenv('ADMIN_IDS'):
    try:
        ADMIN_IDS = [int(id_str.strip()) for id_str in os.getenv('ADMIN_IDS').split(',')
                    if id_str.strip().isdigit()]
    except ValueError:
        logger.error("Некорректный формат ADMIN_IDS в .env файле!")
        ADMIN_IDS = []

SCAN_INTERVAL = int(os.getenv('SCAN_INTERVAL', '15'))  # минуты между сканированиями
CRITICAL_TAG = os.getenv('CRITICAL_TAG', 'Critical')

# Файлы
IGNORED_IPS_FILE = 'ignored_ips.txt'
SCAN_RESULTS_FILE = 'ip_scan_results.xlsx'
SCAN_HISTORY_FILE = 'scan_history.xlsx'

class IPManager:
    def __init__(self):
        self.ignored_ips = self._load_ignored_ips()
        self.last_results = None
        self.critical_changes = []
    
    def _load_ignored_ips(self):
        try:
            with open(IGNORED_IPS_FILE, 'r') as f:
                return set(line.strip() for line in f if line.strip())
        except FileNotFoundError:
            return set()
    
    def save_ignored_ips(self):
        with open(IGNORED_IPS_FILE, 'w') as f:
            for ip in self.ignored_ips:
                f.write(f"{ip}\n")
    
    def add_ignored_ip(self, ip):
        self.ignored_ips.add(ip)
        self.save_ignored_ips()
    
    def remove_ignored_ip(self, ip):
        if ip in self.ignored_ips:
            self.ignored_ips.remove(ip)
            self.save_ignored_ips()
            return True
        return False
    
    def check_critical_changes(self, new_results):
        """Сравнивает новые результаты с предыдущими для критических узлов"""
        if self.last_results is None:
            self.last_results = new_results
            return []
        
        critical_prev = self.last_results[self.last_results['Tags'] == CRITICAL_TAG]
        critical_new = new_results[new_results['Tags'] == CRITICAL_TAG]
        
        changes = []
        
        # Проверка изменений статуса
        for ip in critical_prev['IP']:
            if ip in critical_new['IP'].values:
                prev_status = critical_prev[critical_prev['IP'] == ip]['Status'].values[0]
                new_status = critical_new[critical_new['IP'] == ip]['Status'].values[0]
                
                if prev_status != new_status:
                    changes.append(f"{ip}: {prev_status} → {new_status}")
        
        # Проверка новых критических узлов
        new_critical = set(critical_new['IP']) - set(critical_prev['IP'])
        for ip in new_critical:
            changes.append(f"Новый критический узел: {ip}")
        
        # Проверка пропавших критических узлов
        missing_critical = set(critical_prev['IP']) - set(critical_new['IP'])
        for ip in missing_critical:
            changes.append(f"Критический узел пропал: {ip}")
        
        self.last_results = new_results
        self.critical_changes = changes
        return changes

ip_manager = IPManager()

def arp_scan_network(network: str) -> set:
    """Выполняет ARP-сканирование сети и возвращает set активных IP"""
    try:
        # Создаем ARP-запрос
        arp_request = ARP(pdst=network)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        
        # Отправляем запрос с таймаутом 2 секунды
        answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]
        
        # Собираем ответившие IP
        active_ips = {received.psrc for sent, received in answered}
        logger.info(f"ARP-сканирование обнаружило {len(active_ips)} активных устройств")
        return active_ips
        
    except Scapy_Exception as e:
        logger.error(f"Ошибка ARP-сканирования: {e}")
        return set()
    except Exception as e:
        logger.error(f"Неожиданная ошибка при ARP-сканировании: {e}")
        return set()

async def scan_network(network: str) -> pd.DataFrame:
    """Сканирование сети с использованием ARP"""
    logger.info(f"Начинаю ARP-сканирование сети {network}")
    
    # Получаем все IP в сети
    all_ips = {str(ip) for ip in IPv4Network(network).hosts()}
    logger.info(f"Всего IP-адресов в сети: {len(all_ips)}")
    
    # Получаем активные IP через ARP
    active_ips = arp_scan_network(network)
    
    # Фильтруем игнорируемые IP
    ips_to_process = all_ips - ip_manager.ignored_ips
    logger.info(f"IP для обработки после фильтрации: {len(ips_to_process)}")
    
    # Создаем DataFrame с результатами
    results = []
    for ip in ips_to_process:
        status = 'Online' if ip in active_ips else 'Offline'
        results.append({
            'IP': ip,
            'Status': status,
            'Avg Response (ms)': None,  # ARP не предоставляет это значение
            'Packet Loss (%)': 0 if status == 'Online' else 100,
            'Last Seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'Tags': ''
        })
    
    df = pd.DataFrame(results)
    
    # Загрузка предыдущих тегов
    try:
        prev_df = pd.read_excel(SCAN_RESULTS_FILE)
        df = df.merge(prev_df[['IP', 'Tags']], on='IP', how='left')
        df['Tags'] = df['Tags_y'].combine_first(df['Tags_x'])
        df.drop(['Tags_x', 'Tags_y'], axis=1, inplace=True)
    except FileNotFoundError:
        pass
    
    # Сохранение результатов
    df.to_excel(SCAN_RESULTS_FILE, index=False)
    
    # Добавление в историю
    try:
        history_df = pd.read_excel(SCAN_HISTORY_FILE)
    except FileNotFoundError:
        history_df = pd.DataFrame()
    
    history_df = pd.concat([history_df, df], ignore_index=True)
    history_df.to_excel(SCAN_HISTORY_FILE, index=False)
    
    # Проверка изменений критических узлов
    ip_manager.check_critical_changes(df)
    
    logger.info(f"Сканирование завершено. Найдено активных устройств: {len(active_ips)}")
    return df

async def scheduled_scan(context: CallbackContext):
    """Запланированное сканирование сети"""
    logger.info("Выполнение запланированного ARP-сканирования сети...")
    try:
        df = await scan_network(NETWORK)
        online_count = df[df['Status'] == 'Online'].shape[0]
        
        # Отправка уведомлений об изменениях критических узлов
        if ip_manager.critical_changes:
            message = "🔔 Изменения в критических узлах:\n" + "\n".join(ip_manager.critical_changes)
            for admin_id in ADMIN_IDS:
                await context.bot.send_message(chat_id=admin_id, text=message)
        
        logger.info(f"ARP-сканирование завершено. Активных устройств: {online_count}/{len(df)}")
    except Exception as e:
        logger.error(f"Ошибка при запланированном сканировании: {e}")

def start_scheduler(application):
    """Запуск планировщика для регулярного сканирования"""
    schedule.every(SCAN_INTERVAL).minutes.do(
        lambda: asyncio.run_coroutine_threadsafe(scheduled_scan(application), application.loop)
    )
    
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)
    
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

async def start(update: Update, context: CallbackContext) -> None:
    """Обработчик команды /start"""
    user = update.effective_user
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("❌ У вас нет доступа к этому боту.")
        return
    
    keyboard = [
        ['🔄 Сканировать сеть', '📊 Показать результаты'],
        ['🚫 Игнорируемые IP', '🏷 Управление тегами'],
        ['⏱ Настройки расписания']
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    await update.message.reply_markdown_v2(
        fr'Привет {user.mention_markdown_v2()}\! Я бот для мониторинга сети с использованием ARP\.\n'
        f'Автосканирование каждые {SCAN_INTERVAL} мин\.',
        reply_markup=reply_markup
    )

async def handle_scan(update: Update, context: CallbackContext) -> None:
    """Обработка команды сканирования сети"""
    await update.message.reply_text("🔄 Начинаю ARP-сканирование сети...")
    try:
        df = await scan_network(NETWORK)
        online_count = df[df['Status'] == 'Online'].shape[0]
        await update.message.reply_text(
            f"✅ ARP-сканирование завершено!\n"
            f"Обнаружено активных устройств: {online_count}/{len(df)}\n"
            f"Файл с результатами сохранён: {SCAN_RESULTS_FILE}"
        )
        
        if ip_manager.critical_changes:
            message = "🔔 Изменения в критических узлах:\n" + "\n".join(ip_manager.critical_changes)
            await update.message.reply_text(message)
    except Exception as e:
        logger.error(f"Ошибка сканирования: {e}")
        await update.message.reply_text("❌ Ошибка при сканировании сети!")

async def handle_results(update: Update, context: CallbackContext) -> None:
    """Отправка результатов сканирования"""
    try:
        with open(SCAN_RESULTS_FILE, 'rb') as f:
            await update.message.reply_document(
                document=f,
                caption="📊 Результаты последнего ARP-сканирования сети"
            )
    except FileNotFoundError:
        await update.message.reply_text("ℹ️ Файл с результатами не найден. Сначала выполните сканирование.")

async def handle_ignored_ips(update: Update, context: CallbackContext):
    """Показать список игнорируемых IP"""
    if not ip_manager.ignored_ips:
        await update.message.reply_text("ℹ️ Нет игнорируемых IP-адресов.")
        return
    
    ips = "\n".join(ip_manager.ignored_ips)
    await update.message.reply_text(
        f"🚫 Игнорируемые IP-адреса:\n{ips}\n\n"
        "Чтобы добавить IP в игнорируемые, отправьте его.\n"
        "Чтобы удалить IP из игнорируемых, отправьте 'удалить IP'."
    )

async def handle_tag_management(update: Update, context: CallbackContext):
    """Управление тегами для IP-адресов"""
    try:
        df = pd.read_excel(SCAN_RESULTS_FILE)
        critical_ips = df[df['Tags'] == CRITICAL_TAG]['IP'].tolist()
        
        if critical_ips:
            message = (f"Критические узлы ({CRITICAL_TAG}):\n" + 
                      "\n".join(critical_ips) + 
                      "\n\nДобавить тег: 'тег IP'\nУдалить тег: 'удалить IP'")
        else:
            message = (f"Нет узлов с тегом {CRITICAL_TAG}.\n\n"
                      "Добавить тег: 'тег IP'")
        
        await update.message.reply_text(message)
    except Exception as e:
        logger.error(f"Ошибка управления тегами: {e}")
        await update.message.reply_text("❌ Ошибка при работе с тегами")

async def handle_text(update: Update, context: CallbackContext) -> None:
    """Обработка текстовых сообщений"""
    text = update.message.text.strip()
    user = update.effective_user
    
    if user.id not in ADMIN_IDS:
        await update.message.reply_text("❌ У вас нет доступа к этому боту.")
        return
    
    if text == '🔄 Сканировать сеть':
        await handle_scan(update, context)
    elif text == '📊 Показать результаты':
        await handle_results(update, context)
    elif text == '🚫 Игнорируемые IP':
        await handle_ignored_ips(update, context)
    elif text == '🏷 Управление тегами':
        await handle_tag_management(update, context)
    elif text.startswith('тег '):
        ip = text[4:].strip()
        try:
            df = pd.read_excel(SCAN_RESULTS_FILE)
            df.loc[df['IP'] == ip, 'Tags'] = CRITICAL_TAG
            df.to_excel(SCAN_RESULTS_FILE, index=False)
            await update.message.reply_text(f"✅ Тег '{CRITICAL_TAG}' добавлен для {ip}")
        except Exception as e:
            logger.error(f"Ошибка добавления тега: {e}")
            await update.message.reply_text(f"❌ Не удалось добавить тег для {ip}")
    elif text.startswith('удалить '):
        ip = text[8:].strip()
        try:
            df = pd.read_excel(SCAN_RESULTS_FILE)
            df.loc[df['IP'] == ip, 'Tags'] = ''
            df.to_excel(SCAN_RESULTS_FILE, index=False)
            await update.message.reply_text(f"✅ Тег удалён для {ip}")
        except Exception as e:
            logger.error(f"Ошибка удаления тега: {e}")
            await update.message.reply_text(f"❌ Не удалось удалить тег для {ip}")
    elif text.replace('.', '').isdigit():  # Простая проверка на IP
        ip_manager.add_ignored_ip(text)
        await update.message.reply_text(f"✅ IP {text} добавлен в игнорируемые.")
    else:
        await update.message.reply_text("ℹ️ Неизвестная команда.")

def main() -> None:
    """Запуск бота"""
    if not TOKEN:
        logger.error("Не задан TOKEN в .env файле!")
        return
    
    # Проверка прав для ARP-сканирования
    if os.geteuid() != 0:
        logger.warning("Для ARP-сканирования рекомендуется запускать бота с правами root")
    
    application = Application.builder().token(TOKEN).build()

    # Обработчики команд
    application.add_handler(CommandHandler("start", start))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_text))

    # Запуск планировщика
    start_scheduler(application)
    
    # Запуск бота
    application.run_polling()
    logger.info(f"Бот запущен. Автосканирование каждые {SCAN_INTERVAL} минут")

if __name__ == '__main__':
    main()