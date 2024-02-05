import requests
import schedule
import asyncio
import time
from datetime import datetime, timedelta
from telegram import Bot
from telegram.error import TelegramError
from decouple import config


# Sua função de extração de informações
def extract_info(json_data):
    if 'vulnerabilities' in json_data:
        vulnerabilities = json_data['vulnerabilities']
        extracted_data = []

        for vulnerability in vulnerabilities:
            cve_data = vulnerability.get('cve', {})
            cve_id = cve_data.get('id', None)
            cve_status = cve_data.get('vulnStatus', None)

            descriptions = cve_data.get('descriptions', [])
            description_value_en = None  # Initialize the English description value to None

            for description in descriptions:
                if description.get('lang') == 'en':
                    description_value_en = description.get('value')
                    break  # Stop searching once we find the English description

            configurations = cve_data.get('configurations', [])
            criteria = []

            for config in configurations:
                nodes = config.get('nodes', [])
                for node in nodes:
                    cpe_match = node.get('cpeMatch', [])
                    for cpe in cpe_match:
                        criteria_value = cpe.get('criteria', None)
                        if criteria_value:
                            criteria.append(criteria_value)

            extracted_data.append({
                'cve_id': cve_id,
                'status': cve_status,
                'criteria': criteria,
                'description': description_value_en
            })

        return extracted_data

    return []

async def send_telegram_message(messages, telegram_token, chat_id):
    bot = Bot(token=telegram_token)
    for message in messages:
        try:
            await bot.send_message(chat_id=chat_id, text=message, parse_mode='HTML')
        except TelegramError as e:
            print(f"Erro ao enviar mensagem: {e}")


# Função principal
def main():
    # Defina as informações do Telegram
    telegram_token = config('TELEGRAM_TOKEN', default='')
    chat_id = config('CHAT_ID', default='')
    vendors = config('VENDORS', default='', cast=lambda v: [vendor.strip() for vendor in v.split(',')])

    # Defina as informações da API NVD
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0/"

  # Adicione seus vendors aqui

    # Agende a tarefa diária às 2:30 da manhã
    schedule.every().day.at("02:30").do(run_task, base_url, telegram_token, chat_id, vendors)

    # Mantenha o programa rodando
    while True:
        schedule.run_pending()
        time.sleep(1)

# Função para rodar a tarefa diariamente
def run_task(base_url, telegram_token, chat_id, vendors):
    # Defina as datas inicial e final
    data_inicial = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
    data_final = datetime.now().strftime("%Y-%m-%d")

    # Armazene as mensagens para enviar ao Telegram
    messages = []

    # Loop pelos vendors
    for vendor in vendors:
        url = f"{base_url}?pubStartDate={data_inicial}T00:00:00.000-05:00&pubEndDate={data_final}T23:59:59.999-05:00&keywordSearch={vendor}"

        try:
            response = requests.get(url)
            response.raise_for_status()
            json_data = response.json()
            results = extract_info(json_data)
            
            for result in results:
                message = f"🔒 Nova CVE do <b>{vendor}</b> data: {data_final}\n\n"
                message += f"• ID: {result['cve_id']}\n"
                message += f"• https://nvd.nist.gov/vuln/detail/{result['cve_id']}\n"
                message += f"• Descrição: {result['description']}\n"
                messages.append(message)

        except requests.exceptions.RequestException as e:
            print(f"Erro na requisição para {vendor}: {e}")

        except Exception as e:
            print(f"Erro desconhecido para {vendor}: {e}")

        time.sleep(2 * 60)  # Aguarde 2 minutos entre as requisições

    # Envie as mensagens ao Telegram
    loop = asyncio.get_event_loop()
    loop.run_until_complete(send_telegram_message(messages, telegram_token, chat_id))
    exit()

# Inicie o programa principal
if __name__ == "__main__":
    main()
