import fnmatch
import sys
import time
from threading import Thread
import tarfile
import json

import xlsxwriter

VERSION = '1.3.1'

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
        """Поиск объекта по его uid. Используется кеширование.

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
        """Расшифровка объекта. Используется кеширование.

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
        """Раскрытие группы объектов. Используется кеширование.

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
    
    def write(self, ws: xlsxwriter.workbook.Worksheet, row: int, extra_row:int, col:int, extra_col:int, data:str, format:xlsxwriter.workbook.Format):
        """Обертка для функций xlsxwriter merge_range и write.

        Args:
            ws (xlsxwriter.workbook.Worksheet): рабочая страница
            row (int): номер строка
            extra_row (int): сколько последующих строк объеденить
            col (int): номер столбца
            extra_col (int): сколько последующих столбцов объеденить
            data (str): данные
            format (xlsxwriter.workbook.Format): формат
        """
        if extra_row or extra_col:
            ws.merge_range(row, col, row + extra_row, col + extra_col, data, format)
        else:
            ws.write(row, col, data, format)

    def truncate_string(self, string) -> list:
        """Разбитие строки на несколько

        Args:
            string (_type_): исходная строка

        Returns:
            list: массив строк
        """
        result = []
        while len(string) > 32767:
            last_new_line = string[:32767].rindex('\n')
            result.append(string[:last_new_line])
            string = string[last_new_line+1:]
        result.append(string)
        return result

    def gen_firewall_sheet(self, name: str, net_table: json) -> None:
        """Генерация страницы с правилами файрволла

        Args:
            name (str): Имя страницы
            net_table (json): объект с правилами файрволла
        """

        ws = self.wb.add_worksheet(name)
        ws.set_column('A:A', 5)
        ws.set_column('B:B', 10)
        ws.set_column('C:C', 20)
        ws.set_column('D:E', 40)
        ws.set_column('F:F', 15)
        ws.set_column('G:G', 20)
        ws.set_column('H:I', 10)
        ws.set_column('J:J', 15)
        ws.set_column('K:K', 40)
        ws.set_column('L:L', 40)

        self.write(ws, 0, 0, 0, 0, '№', self.style_title)
        self.write(ws, 0, 0, 1, 0, 'Hits', self.style_title)
        self.write(ws, 0, 0, 2, 0, 'Name', self.style_title)
        self.write(ws, 0, 0, 3, 0, 'Source', self.style_title)
        self.write(ws, 0, 0, 4, 0, 'Destinaton', self.style_title)
        self.write(ws, 0, 0, 5, 0, 'VPN', self.style_title)
        self.write(ws, 0, 0, 6, 0, 'Service', self.style_title)
        self.write(ws, 0, 0, 7, 0, 'Action', self.style_title)
        self.write(ws, 0, 0, 8, 0, 'Track', self.style_title)
        self.write(ws, 0, 0, 9, 0, 'Time', self.style_title)
        self.write(ws, 0, 0, 10, 0, 'Install on', self.style_title)
        self.write(ws, 0, 0, 11, 0, 'Comment', self.style_title)
        ws.freeze_panes(1, 0)

        row = 1
        for entry in net_table:
            if entry['type'] == "place-holder":
                self.write(ws, row, 0, 0, 0, str(entry['rule-number']), self.style_placeholder)
                self.write(ws, row, 0, 1, 10, entry['name'], self.style_placeholder)
            elif entry['type'] == "access-section":
                self.write(ws, row, 0, 0, 11, entry['name'], self.style_section)
            else:
                rule_number = str(entry['rule-number'])
                try:
                    hits = str(entry['hits']['value'])
                except KeyError:
                    hits = ''
                try:
                    name = entry['name']
                except KeyError:
                    name = ''
                source = self.truncate_string(self.list_to_str(self.decode_uid_list(self.expand_group(entry['source']))))
                s_trunkated_len = len(source)
                destination = self.truncate_string(self.list_to_str(self.decode_uid_list(self.expand_group(entry['destination']))))
                d_trunkated_len = len(destination)
                extra_rows = max(s_trunkated_len, d_trunkated_len) - 1
                vpn = self.list_to_str(self.decode_uid_list(self.expand_group(entry['vpn'])))
                service = self.list_to_str(self.decode_uid_list(self.expand_group(entry['service'])))
                action = self.list_to_str(self.decode_uid(entry['action']))
                track = self.list_to_str(self.decode_uid(entry['track']['type']))
                time = self.list_to_str(self.decode_uid_list(self.expand_group(entry['time'])))
                install_on = self.list_to_str(self.decode_uid_list(self.expand_group(entry['install-on'])))
                comments = entry['comments']
                
                self.write(ws, row, extra_rows, 0, 0, rule_number, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 1, 0, hits, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 2, 0, name, self.style_picker(entry['enabled']))
                row_for_data = extra_rows // s_trunkated_len
                s_rows_remain = extra_rows
                for i in range(s_trunkated_len):
                    if s_rows_remain < row_for_data:
                        row_for_data = s_rows_remain
                    self.write(ws, row+i, row_for_data, 3, 0, source[i], self.style_picker(entry['enabled'], entry['source-negate']))
                    s_rows_remain = s_rows_remain - row_for_data
                row_for_data = extra_rows // d_trunkated_len
                d_rows_remain = extra_rows
                for i in range(d_trunkated_len):
                    if d_rows_remain < row_for_data:
                        row_for_data = d_rows_remain
                    self.write(ws, row+i, row_for_data, 4, 0, destination[i], self.style_picker(entry['enabled'], entry['destination-negate']))
                    d_rows_remain = d_rows_remain - row_for_data
                self.write(ws, row, extra_rows, 5, 0, vpn, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 6, 0, service, self.style_picker(entry['enabled'], entry['service-negate']))
                self.write(ws, row, extra_rows, 7, 0, action, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 8, 0, track, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 9, 0, time, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 10, 0, install_on, self.style_picker(entry['enabled']))
                self.write(ws, row, extra_rows, 11, 0, comments, self.style_picker(entry['enabled']))
                row = row + extra_rows
            row = row + 1

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

        self.write(ws, 0, 0, 0, 0, '№', self.style_title)
        self.write(ws, 0, 0, 1, 0, 'Original Source', self.style_title)
        self.write(ws, 0, 0, 2, 0, 'Original Destination', self.style_title)
        self.write(ws, 0, 0, 3, 0, 'Original Services', self.style_title)
        self.write(ws, 0, 0, 4, 0, 'Translated Source', self.style_title)
        self.write(ws, 0, 0, 5, 0, 'Translated Destination', self.style_title)
        self.write(ws, 0, 0, 6, 0, 'Translated Services', self.style_title)
        self.write(ws, 0, 0, 7, 0, 'Install on', self.style_title)
        self.write(ws, 0, 0, 8, 0, 'Comments', self.style_title)
        ws.freeze_panes(1, 0)

        row = 1
        for entry in self._nat_:
            if entry['type'] == "nat-section":
                self.write(ws, row, 0, 0, 8, entry['name'], self.style_section)
            else:
                rule_number = str(entry['rule-number'])
                o_source = self.list_to_str(self.decode_uid_list(self.expand_group(entry['original-source'])))
                o_destination = self.list_to_str(self.decode_uid_list(self.expand_group(entry['original-destination'])))
                o_service = self.list_to_str(self.decode_uid_list(self.expand_group(entry['original-service'])))
                t_source = self.list_to_str(self.decode_uid_list(self.expand_group(entry['translated-source'])))
                t_destination = self.list_to_str(self.decode_uid_list(self.expand_group(entry['translated-destination'])))
                t_service = self.list_to_str(self.decode_uid_list(self.expand_group(entry['translated-service'])))
                install_on = self.list_to_str(self.decode_uid_list(self.expand_group(entry['install-on'])))
                comments = entry['comments']
                
                self.write(ws, row, 0, 0, 0, rule_number, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 1, 0, o_source, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 2, 0, o_destination, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 3, 0, o_service, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 4, 0, t_source, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 5, 0, t_destination, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 6, 0, t_service, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 7, 0, install_on, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 8, 0, comments, self.style_picker(entry['enabled']))
            row = row + 1

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

        self.write(ws, 0, 0, 0, 0, '№', self.style_title)
        self.write(ws, 0, 0, 1, 0, 'Name', self.style_title)
        self.write(ws, 0, 0, 2, 0, 'Protected Scope', self.style_title)
        self.write(ws, 0, 0, 3, 0, 'Source', self.style_title)
        self.write(ws, 0, 0, 4, 0, 'Destination', self.style_title)
        self.write(ws, 0, 0, 5, 0, 'Protection/Site', self.style_title)
        self.write(ws, 0, 0, 6, 0, 'Services', self.style_title)
        self.write(ws, 0, 0, 7, 0, 'Action', self.style_title)
        self.write(ws, 0, 0, 8, 0, 'Track', self.style_title)
        self.write(ws, 0, 0, 9, 0, 'Install on', self.style_title)
        self.write(ws, 0, 0, 10, 0, 'Comments', self.style_title)
        ws.freeze_panes(1, 0)

        row = 1
        for entry in self._tp_:
            if entry['type'] == "threat-section":
                self.write(ws, row, 0, 0, 10, entry['name'], self.style_section)
            else:
                rule_number = str(entry['rule-number'])
                try:
                    name = entry['name']
                except KeyError:
                    name = ''
                p_scope = self.list_to_str(self.decode_uid_list(self.expand_group(entry['protected-scope'])))
                source = self.list_to_str(self.decode_uid_list(self.expand_group(entry['source'])))
                destination = self.list_to_str(self.decode_uid_list(self.expand_group(entry['destination'])))
                p_site = 'N/A'
                service = self.list_to_str(self.decode_uid_list(self.expand_group(entry['service'])))
                action = self.list_to_str(self.decode_uid(entry['action']))
                track = self.list_to_str(self.decode_uid(entry['track']))
                install_on = self.list_to_str(self.decode_uid_list(self.expand_group(entry['install-on'])))
                comments = entry['comments']

                self.write(ws, row, 0, 0, 0, rule_number, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 1, 0, name, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 2, 0, p_scope, self.style_picker(entry['enabled'], entry['protected-scope-negate']))
                self.write(ws, row, 0, 3, 0, source, self.style_picker(entry['enabled'], entry['source-negate']))
                self.write(ws, row, 0, 4, 0, destination, self.style_picker(entry['enabled'], entry['destination-negate']))
                self.write(ws, row, 0, 5, 0, p_site, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 6, 0, service, self.style_picker(entry['enabled'], entry['service-negate']))
                self.write(ws, row, 0, 7, 0, action, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 8, 0, track, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 9, 0, install_on, self.style_picker(entry['enabled']))
                self.write(ws, row, 0, 10, 0, comments, self.style_picker(entry['enabled']))
            row = row + 1


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
