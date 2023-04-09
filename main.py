import fnmatch
import sys
import time
from threading import Thread
import tarfile
import json

import xlsxwriter

VERSION = '1.3'

class Cp2xlsx:
    def __init__(self, package: str) -> None:
        self.load_package(package)
        self.verify_package()
        self.package_name = self._index_['policyPackages'][0]['packageName']
        self.wb = xlsxwriter.Workbook(f'{self.package_name}.xlsx')
        self.init_styles()
        self._cached_groups_ = dict()
        self._cached_objects_ = dict()
        self._cached_uids_ = dict()
        threads = []
        if self._gnet_:
            threads.append(Thread(
                target=self.thread_wrapper,
                args=(self.gen_firewall_sheet,
                      ('Global Firewall', self._gnet_),
                      "Global Firewall"
                      )
                )
            )
        if self._net_:
            threads.append(Thread(
                target=self.thread_wrapper,
                args=(self.gen_firewall_sheet,
                      ('Firewall', self._net_),
                      "Firewall"
                      )
                )
            )
        if self._nat_:
            threads.append(Thread(
                target=self.thread_wrapper,
                args=(self.gen_nat_sheet,
                      (),
                      "NAT"
                     )
                )
            )
        if self._tp_:
            threads.append(Thread(
                target=self.thread_wrapper,
                args=(self.gen_tp_sheet,
                      (),
                      "TP"
                      )
                )
            )
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # self.gen_firewall_sheet('Global Firewall', self._gnet_)
        # self.gen_firewall_sheet('Firewall', self._net_)
        # self.gen_nat_sheet()
        # self.gen_tp_sheet()
        self.wb.close()

    def thread_wrapper(self, target, args: tuple, name: str):
        """Обертка для замера скорости выполнения функций

        Args:
            target (function): функция
            args (tuple): аргументы
            name (str): имя обертки

        Returns:
            any: результат выполнения target функции
        """
        start_time = time.perf_counter()
        print(f"Thread {name} started.")
        result = target(*args)
        stop_time = time.perf_counter()
        print(f"Thread {name} finished in {stop_time-start_time: 0.2f}s.")
        return result

    def get_filename(self) -> str:
        """Получаем имя файла xlsx

        Returns:
            str: имя файла
        """
        return self.wb.filename

    def verify_package(self) -> None:
        """Проверка на наличие требуемых файлов в архиве политики
        """
        if self._index_ == None:
            print("Файл index.json не найден! Проверьте целостность архива.")
            input("Нажмите Enter для выхода.")
            quit()
        if self._objects_ == None:
            print("Файл *objects.json не найден! Проверьте целостность архива.")
            input("Нажмите Enter для выхода.")
            quit()
        if self._gnet_ == None:
            print("Файл '*Network-Global*.json' не найден. Пропускаем таблицу Global Firewall...")
        if self._net_ == None:
            print("Файл '*Network*.json' не найден. Пропускаем таблицу Firewall...")
        if self._nat_ == None:
            print("Файл '*NAT*.json' не найден. Пропускаем таблицу NAT...")
        if self._tp_ == None:
            print("Файл '*Threat Prevention*.json' не найден. Пропускаем таблицу Threat Prevention...")
        if self._gwobj_ == None:
            print("Файл '*gateway_objects.json' не найден.")

    def init_styles(self) -> None:
        """Инициализация стилей таблицы
        """
        default = {'valign': 'vcenter', 'border': True}
        self.style_default = self.wb.add_format(default)

        title = {**default, **{'font_size': '12', 'bold': True, 'bottom': True, 'align': 'center', 'font_color': 'white', 'bg_color': 'gray'}}
        self.style_title = self.wb.add_format(title)
        
        section = {**default, **{'bold': True, 'align': 'center', 'bg_color': 'yellow'}}
        self.style_section = self.wb.add_format(section)

        placeholder = {**default, **{'bold': True, 'align': 'left', 'bg_color': 'green'}}
        self.style_placeholder = self.wb.add_format(placeholder)

        data = {**default, **{'text_wrap': True, 'align': 'left', 'valign': 'top'}}
        self.style_data = self.wb.add_format(data)

        data_neg = {**data, **{'font_color': 'red', 'italic': True}}
        self.style_data_neg = self.wb.add_format(data_neg)

        data_dis = {**data, **{'bg_color': '#c8c8c8'}}
        self.style_data_dis = self.wb.add_format(data_dis)

        data_dis_neg = {**data_neg, **data_dis}
        self.style_data_dis_neg = self.wb.add_format(data_dis_neg)

    def style_picker(self, enabled: bool = True, negated: bool = False) -> xlsxwriter.workbook.Format:
        """Возвращает стиль для ячейки правила.

        Args:
            enabled (bool, optional): Правило включено. Defaults to True.
            negated (bool, optional): Значение ячейки отрицательное. Defaults to False.

        Returns:
            xlsxwriter.workbook.Format: Стиль
        """
        if enabled and not negated:
            return self.style_data
        if enabled and negated:
            return self.style_data_neg
        if not enabled and not negated:
            return self.style_data_dis
        if not enabled and negated:
            return self.style_data_dis_neg

    def load_package(self, package: str) -> None:
        """Загрузка файлов json из архива политики

        Args:
            package (str): путь до архива
        """
        self._index_ = None
        self._net_ = None
        self._gnet_ = None
        self._nat_ = None
        self._gwobj_ = None
        self._objects_ = None
        self._tp_ = None
        with tarfile.open(package, "r:gz") as archive:
            for file in archive:
                if fnmatch.fnmatch(file.name, 'index.json'):
                    with archive.extractfile(file) as f:
                        self._index_ = json.loads(f.readline())
                    continue
                if fnmatch.fnmatch(file.name, '*Network-Global*.json'):
                    with archive.extractfile(file) as f:
                        self._gnet_ = json.loads(f.readline())
                    continue
                if fnmatch.fnmatch(file.name, '*Network*.json'):
                    with archive.extractfile(file) as f:
                        self._net_ = json.loads(f.readline())
                    continue
                if fnmatch.fnmatch(file.name, '*NAT*.json'):
                    with archive.extractfile(file) as f:
                        self._nat_ = json.loads(f.readline())
                    continue
                if fnmatch.fnmatch(file.name, '*Threat Prevention*.json'):
                    with archive.extractfile(file) as f:
                        self._tp_ = json.loads(f.readline())
                    continue
                if fnmatch.fnmatch(file.name, '*gateway_objects.json'):
                    with archive.extractfile(file) as f:
                        self._gwobj_ = json.loads(f.readline())
                    continue
                if fnmatch.fnmatch(file.name, '*objects.json'):
                    with archive.extractfile(file) as f:
                        self._objects_ = json.loads(f.readline())
                    continue

    def find_obj_by_uid(self, uid: str) -> dict:
        """Поиск объекта по его uid. Используется кэширование.

        Args:
            uid (str): uid объекта

        Returns:
            dict: объект
        """
        if uid in self._cached_uids_:
            return self._cached_uids_[uid]
        for obj in self._objects_:
            if obj['uid'] == uid:
                self._cached_uids_[uid] = obj
                return obj

    def decode_uid(self, uid: str) -> str:
        """Расшифровка объекта. Используется кэширование.

        Args:
            uid (str): uid объекта

        Returns:
            str: описание объекта
        """
        if uid in self._cached_objects_:
            return self._cached_objects_[uid]
        obj = self.find_obj_by_uid(uid)
        result = obj['name']
        if not obj:
            result = "!OBJECT NOT FOUND!"
        if 'host' in obj['type'] or 'gateway' in obj['type'] or 'cluster' in obj['type']:
            result = f"{obj['name']} / {obj['ipv4-address']}"
        if obj['type'] == 'network':
            result = f"{obj['name']} / {obj['subnet4']}/{obj['mask-length4']}"
        if obj['type'] == 'service-tcp':
            result = f"tcp/{obj['port']}"
        if obj['type'] == 'service-udp':
            result = f"udp/{obj['port']}"
        self._cached_objects_[uid] = result
        return  result

    def decode_uid_list(self, uids: list) -> list:
        """Расшифровка массива объектов

        Args:
            uids (list): массив uid объектов

        Returns:
            list: массив описаний объектов
        """
        result = list()
        for uid in uids:
            result.append(self.decode_uid(uid))
        return result

    def list_to_str(self, l: list) -> str:
        """Преобразование массива в строку

        Args:
            l (list): массив объектов

        Returns:
            str: строка объектов
        """
        if type(l) is not list:
            return l
        return '\n'.join(l)

    def expand_group(self, uids: list) -> list:
        """Раскрытие группы объектов. Используется кэширование.

        Args:
            uids (list): массив uid объектов

        Returns:
            list: список объектов в группе
        """
        if type(uids) is str:
            uids = [uids]
        result = list()
        for uid in uids:
            if type(uid) is not str:
                uid = uid['uid']
            if uid in self._cached_groups_:
                result = result + self._cached_groups_[uid]
                continue
            obj = self.find_obj_by_uid(uid)
            if 'group' in obj['type']:
                expanded = self.expand_group(obj['members'])
                result = result + expanded
                self._cached_groups_[uid] = expanded
            else:
                result = result + [uid]
        # возвращаем результат без дубликатов
        return list(dict.fromkeys(result))

    def gen_firewall_sheet(self, name: str, net_table: json) -> None:
        """Генерация страницы с правилами файрволла

        Args:
            name (str): Имя страницы
            net_table (json): объект с правилами файрволла
        """

        ws = self.wb.add_worksheet(name)
        ws.set_column('A:A', 5)
        ws.set_column('B:B', 5)
        ws.set_column('C:C', 20)
        ws.set_column('D:E', 40)
        ws.set_column('F:F', 15)
        ws.set_column('G:G', 20)
        ws.set_column('H:I', 10)
        ws.set_column('J:J', 15)
        ws.set_column('K:K', 40)
        ws.set_column('L:L', 40)

        ws.write('A1', '№', self.style_title)
        ws.write('B1', 'Hits', self.style_title)
        ws.write('C1', 'Name', self.style_title)
        ws.write('D1', 'Source', self.style_title)
        ws.write('E1', 'Destinaton', self.style_title)
        ws.write('F1', 'VPN', self.style_title)
        ws.write('G1', 'Service', self.style_title)
        ws.write('H1', 'Action', self.style_title)
        ws.write('I1', 'Track', self.style_title)
        ws.write('J1', 'Time', self.style_title)
        ws.write('K1', 'Install on', self.style_title)
        ws.write('L1', 'Comment', self.style_title)
        ws.freeze_panes(1, 0)

        for i in range(len(net_table)):
            row = i + 1
            if net_table[i]['type'] == "place-holder":
                ws.write(row, 0, net_table[i]['rule-number'], self.style_placeholder)
                ws.merge_range(row, 1, row, 11, net_table[i]['name'], self.style_placeholder)
            elif net_table[i]['type'] == "access-section":
                ws.merge_range(row, 0, row, 11, net_table[i]['name'], self.style_section)
            else:
                ws.write(row, 0, net_table[i]['rule-number'], self.style_picker(net_table[i]['enabled']))
                
                try:
                    hits = net_table[i]['hits']['value']
                except KeyError:
                    hits = ''
                ws.write(row, 1, hits, self.style_picker(net_table[i]['enabled']))
                
                try:
                    name = net_table[i]['name']
                except KeyError:
                    name = ''
                ws.write(row, 2, name, self.style_picker(net_table[i]['enabled']))
                
                source = self.list_to_str(self.decode_uid_list(self.expand_group(net_table[i]['source'])))
                ws.write(row, 3, source, self.style_picker(net_table[i]['enabled'], net_table[i]['source-negate']))
                
                destination = self.list_to_str(self.decode_uid_list(self.expand_group(net_table[i]['destination'])))
                ws.write(row, 4, destination, self.style_picker(net_table[i]['enabled'], net_table[i]['destination-negate']))
                
                vpn = self.list_to_str(self.decode_uid_list(self.expand_group(net_table[i]['vpn'])))
                ws.write(row, 5, vpn, self.style_picker(net_table[i]['enabled']))
                
                service = self.list_to_str(self.decode_uid_list(self.expand_group(net_table[i]['service'])))
                ws.write(row, 6, service, self.style_picker(net_table[i]['enabled'], net_table[i]['service-negate']))
                
                action = self.list_to_str(self.decode_uid(net_table[i]['action']))
                ws.write(row, 7, action, self.style_picker(net_table[i]['enabled']))
                
                track = self.list_to_str(self.decode_uid(net_table[i]['track']['type']))
                ws.write(row, 8, track, self.style_picker(net_table[i]['enabled']))
                
                time = self.list_to_str(self.decode_uid_list(self.expand_group(net_table[i]['time'])))
                ws.write(row, 9, time, self.style_picker(net_table[i]['enabled']))
                
                install_on = self.list_to_str(self.decode_uid_list(self.expand_group(net_table[i]['install-on'])))
                ws.write(row, 10, install_on, self.style_picker(net_table[i]['enabled']))
                
                ws.write(row, 11, net_table[i]['comments'], self.style_picker(net_table[i]['enabled']))

    def gen_nat_sheet(self) -> None:
        """Генерация странцы NAT
        """
        ws = self.wb.add_worksheet('NAT')
        ws.set_column('A:A', 5)
        ws.set_column('B:C', 50)
        ws.set_column('D:D', 20)
        ws.set_column('E:F', 50)
        ws.set_column('G:G', 20)
        ws.set_column('I:I', 50)
        ws.set_column('H:H', 40)

        ws.write('A1', '№', self.style_title)
        ws.write('B1', 'Original Source', self.style_title)
        ws.write('C1', 'Original Destination', self.style_title)
        ws.write('D1', 'Original Services', self.style_title)
        ws.write('E1', 'Translated Source', self.style_title)
        ws.write('F1', 'Translated Destination', self.style_title)
        ws.write('G1', 'Translated Services', self.style_title)
        ws.write('H1', 'Install on', self.style_title)
        ws.write('I1', 'Comments', self.style_title)
        ws.freeze_panes(1, 0)

        for i in range(len(self._nat_)):
            row = i + 1
            if self._nat_[i]['type'] == "nat-section":
                ws.merge_range(row, 0, row, 8, self._nat_[i]['name'], self.style_section)
            else:
                ws.write(row, 0, self._nat_[i]['rule-number'], self.style_picker(self._nat_[i]['enabled']))
                
                o_source = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['original-source'])))
                ws.write(row, 1, o_source, self.style_picker(self._nat_[i]['enabled']))
                
                o_destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['original-destination'])))
                ws.write(row, 2, o_destination, self.style_picker(self._nat_[i]['enabled']))
                
                o_service = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['original-service'])))
                ws.write(row, 3, o_service, self.style_picker(self._nat_[i]['enabled']))
                
                t_source = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['translated-source'])))
                ws.write(row, 4, t_source, self.style_picker(self._nat_[i]['enabled']))
                
                t_destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['translated-destination'])))
                ws.write(row, 5, t_destination, self.style_picker(self._nat_[i]['enabled']))
                
                t_service = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['translated-service'])))
                ws.write(row, 6, t_service, self.style_picker(self._nat_[i]['enabled']))
                
                install_on = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['install-on'])))
                ws.write(row, 7, install_on, self.style_picker(self._nat_[i]['enabled']))

                ws.write(row, 8, self._nat_[i]['comments'], self.style_picker(self._nat_[i]['enabled']))

    def gen_tp_sheet(self) -> None:
        """Генерация страницы Threat prevention
        """
        ws = self.wb.add_worksheet('Threat Prevention')
        ws.set_column('A:A', 5)
        ws.set_column('B:C', 20)
        ws.set_column('D:E', 50)
        ws.set_column('F:F', 20)
        ws.set_column('G:I', 10)
        ws.set_column('J:J', 50)
        ws.set_column('K:K', 40)

        ws.write('A1', '№', self.style_title)
        ws.write('B1', 'Name', self.style_title)
        ws.write('C1', 'Protected Scope', self.style_title)
        ws.write('D1', 'Source', self.style_title)
        ws.write('E1', 'Destination', self.style_title)
        ws.write('F1', 'Protection/Site', self.style_title)
        ws.write('G1', 'Services', self.style_title)
        ws.write('H1', 'Action', self.style_title)
        ws.write('I1', 'Track', self.style_title)
        ws.write('J1', 'Install on', self.style_title)
        ws.write('K1', 'Comments', self.style_title)
        ws.freeze_panes(1, 0)

        for i in range(len(self._tp_)):
            row = i + 1
            if self._tp_[i]['type'] == "threat-section":
                ws.merge_range(row, 0, row, 10, self._tp_[i]['name'], self.style_section)
            else:
                ws.write(row, 0, self._tp_[i]['rule-number'], self.style_picker(self._tp_[i]['enabled']))

                try:
                    name = self._tp_[i]['name']
                except KeyError:
                    name = ''
                ws.write(row, 1, name, self.style_picker(self._tp_[i]['enabled']))

                p_scope = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['protected-scope'])))
                ws.write(row, 2, p_scope, self.style_picker(self._tp_[i]['enabled'], self._tp_[i]['protected-scope-negate']))

                source = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['source'])))
                ws.write(row, 3, source, self.style_picker(self._tp_[i]['enabled'], self._tp_[i]['source-negate']))

                destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['destination'])))
                ws.write(row, 4, destination, self.style_picker(self._tp_[i]['enabled'], self._tp_[i]['destination-negate']))

                p_site = 'N/A'
                ws.write(row, 5, p_site, self.style_picker(self._tp_[i]['enabled']))

                service = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['service'])))
                ws.write(row, 6, service, self.style_picker(self._tp_[i]['enabled'], self._tp_[i]['service-negate']))

                action = self.list_to_str(self.decode_uid(self._tp_[i]['action']))
                ws.write(row, 7, action, self.style_picker(self._tp_[i]['enabled']))

                track = self.list_to_str(self.decode_uid(self._tp_[i]['track']))
                ws.write(row, 8, track, self.style_picker(self._tp_[i]['enabled']))

                install_on = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['install-on'])))
                ws.write(row, 9, install_on, self.style_picker(self._tp_[i]['enabled']))

                ws.write(row, 10, self._tp_[i]['comments'], self.style_picker(self._tp_[i]['enabled']))


def main(args):
    print(f"cp2xlsx80 ver. {VERSION}")
    if len(args) > 1:
        start_time = time.perf_counter()
        cp = Cp2xlsx(args[1])
        file = cp.get_filename()
        end_time = time.perf_counter()
        print(f'Файл {file} преобразован за {end_time - start_time: 0.2f} секунды.')
    else:
        # Cp2xlsx('show_package-2022-10-03_15-44-34.tar.gz')
        # Cp2xlsx('show_package-2023-03-13_09-55-13.tar.gz')
        # Cp2xlsx('show_package-2023-03-24_13-31-01.tar.gz')
        print("Использование: перетащите архив с выгрузкой из утилиты web_api_show_package.sh на этот файл.")
    input("Для выхода нажмите Enter")


if __name__ == "__main__":
    main(sys.argv)
