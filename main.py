import os
import logging
import pandas as pd
import schedule
import time
import threading
from pythonping import ping
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext
from dotenv import load_dotenv
from ipaddress import IPv4Network
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime

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
ADMIN_IDS = list(map(int, os.getenv('ADMIN_IDS', '').split(','))) if os.getenv('ADMIN_IDS') else []
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

def scan_network(network: str) -> pd.DataFrame:
    """Сканирование сети и возврат результатов в DataFrame"""
    ips = [str(ip) for ip in IPv4Network(network).hosts()]
    results = []
    
    def ping_ip(ip):
        try:
            response = ping(ip, count=2, timeout=1)
            return {
                'IP': ip,
                'Status': 'Online' if response.success() else 'Offline',
                'Avg Response (ms)': response.rtt_avg_ms if response.success() else None,
                'Packet Loss (%)': response.packet_loss * 100 if response.success() else 100,
                'Last Seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Tags': ''
            }
        except Exception:
            return {
                'IP': ip,
                'Status': 'Error',
                'Avg Response (ms)': None,
                'Packet Loss (%)': 100,
                'Last Seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'Tags': ''
            }
    
    with ThreadPoolExecutor(max_workers=50) as executor:
        results = list(executor.map(ping_ip, ips))
    
    df = pd.DataFrame(results)
    
    # Загрузка предыдущих результатов для сохранения тегов
    try:
        prev_df = pd.read_excel(SCAN_RESULTS_FILE)
        df = df.merge(prev_df[['IP', 'Tags']], on='IP', how='left')
        df['Tags'] = df['Tags_y'].combine_first(df['Tags_x'])
        df.drop(['Tags_x', 'Tags_y'], axis=1, inplace=True)
    except FileNotFoundError:
        pass
    
    # Фильтрация игнорируемых IP
    df = df[~df['IP'].isin(ip_manager.ignored_ips)]
    
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
    
    return df

def scheduled_scan(context: CallbackContext):
    """Запланированное сканирование сети"""
    logger.info("Выполнение запланированного сканирования сети...")
    try:
        df = scan_network(NETWORK)
        online_count = df[df['Status'] == 'Online'].shape[0]
        
        # Отправка уведомлений об изменениях критических узлов
        if ip_manager.critical_changes:
            message = "🔔 Изменения в критических узлах:\n" + "\n".join(ip_manager.critical_changes)
            for admin_id in ADMIN_IDS:
                context.bot.send_message(chat_id=admin_id, text=message)
        
        logger.info(f"Сканирование завершено. Онлайн: {online_count}/{len(df)}")
    except Exception as e:
        logger.error(f"Ошибка при запланированном сканировании: {e}")

def start_scheduler(updater):
    """Запуск планировщика для регулярного сканирования"""
    schedule.every(SCAN_INTERVAL).minutes.do(
        scheduled_scan, 
        context=updater.dispatcher
    )
    
    def run_scheduler():
        while True:
            schedule.run_pending()
            time.sleep(1)
    
    scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
    scheduler_thread.start()

def start(update: Update, context: CallbackContext) -> None:
    """Обработчик команды /start"""
    user = update.effective_user
    if user.id not in ADMIN_IDS:
        update.message.reply_text("❌ У вас нет доступа к этому боту.")
        return
    
    keyboard = [
        ['🔄 Сканировать сеть', '📊 Показать результаты'],
        ['🚫 Игнорируемые IP', '🏷 Управление тегами'],
        ['⏱ Настройки расписания']
    ]
    reply_markup = ReplyKeyboardMarkup(keyboard, resize_keyboard=True)
    
    update.message.reply_markdown_v2(
        fr'Привет {user.mention_markdown_v2()}\! Я бот для мониторинга сети\.\n'
        f'Автосканирование каждые {SCAN_INTERVAL} мин\.',
        reply_markup=reply_markup
    )

def handle_tag_management(update: Update, context: CallbackContext):
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
        
        update.message.reply_text(message)
    except Exception as e:
        logger.error(f"Ошибка управления тегами: {e}")
        update.message.reply_text("❌ Ошибка при работе с тегами")

def handle_text(update: Update, context: CallbackContext) -> None:
    """Обработка текстовых сообщений"""
    text = update.message.text.strip()
    user = update.effective_user
    
    if user.id not in ADMIN_IDS:
        update.message.reply_text("❌ У вас нет доступа к этому боту.")
        return
    
    if text == '🔄 Сканировать сеть':
        update.message.reply_text("🔄 Начинаю сканирование сети...")
        try:
            df = scan_network(NETWORK)
            online_count = df[df['Status'] == 'Online'].shape[0]
            update.message.reply_text(
                f"✅ Сканирование завершено!\n"
                f"Обнаружено устройств: {online_count}/{len(df)}\n"
                f"Файл с результатами сохранён: {SCAN_RESULTS_FILE}"
            )
            
            if ip_manager.critical_changes:
                message = "🔔 Изменения в критических узлах:\n" + "\n".join(ip_manager.critical_changes)
                update.message.reply_text(message)
        except Exception as e:
            logger.error(f"Ошибка сканирования: {e}")
            update.message.reply_text("❌ Ошибка при сканировании сети!")
    
    elif text == '📊 Показать результаты':
        try:
            with open(SCAN_RESULTS_FILE, 'rb') as f:
                update.message.reply_document(
                    document=f,
                    caption="📊 Результаты последнего сканирования сети"
                )
        except FileNotFoundError:
            update.message.reply_text("ℹ️ Файл с результатами не найден. Сначала выполните сканирование.")
    
    elif text == '🚫 Игнорируемые IP':
        handle_ignored_ips(update)
    
    elif text == '🏷 Управление тегами':
        handle_tag_management(update, context)
    
    elif text.startswith('тег '):
        ip = text[4:].strip()
        try:
            df = pd.read_excel(SCAN_RESULTS_FILE)
            df.loc[df['IP'] == ip, 'Tags'] = CRITICAL_TAG
            df.to_excel(SCAN_RESULTS_FILE, index=False)
            update.message.reply_text(f"✅ Тег '{CRITICAL_TAG}' добавлен для {ip}")
        except Exception as e:
            logger.error(f"Ошибка добавления тега: {e}")
            update.message.reply_text(f"❌ Не удалось добавить тег для {ip}")
    
    elif text.startswith('удалить '):
        ip = text[8:].strip()
        try:
            df = pd.read_excel(SCAN_RESULTS_FILE)
            df.loc[df['IP'] == ip, 'Tags'] = ''
            df.to_excel(SCAN_RESULTS_FILE, index=False)
            update.message.reply_text(f"✅ Тег удалён для {ip}")
        except Exception as e:
            logger.error(f"Ошибка удаления тега: {e}")
            update.message.reply_text(f"❌ Не удалось удалить тег для {ip}")
    
    elif text.replace('.', '').isdigit():  # Простая проверка на IP
        ip_manager.add_ignored_ip(text)
        update.message.reply_text(f"✅ IP {text} добавлен в игнорируемые.")
    
    else:
        update.message.reply_text("ℹ️ Неизвестная команда.")

def main() -> None:
    """Запуск бота"""
    if not TOKEN:
        logger.error("Не задан TOKEN в .env файле!")
        return
    
    updater = Updater(TOKEN)
    dispatcher = updater.dispatcher

    # Обработчики команд
    dispatcher.add_handler(CommandHandler("start", start))
    dispatcher.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_text))

    # Запуск планировщика
    start_scheduler(updater)
    
    # Запуск бота
    updater.start_polling()
    logger.info(f"Бот запущен. Автосканирование каждые {SCAN_INTERVAL} минут")
    updater.idle()

if __name__ == '__main__':
    main()