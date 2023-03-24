import fnmatch
import sys
import time
from threading import Thread
import tarfile
import json

import xlsxwriter

VERSION = '1.2a'

class Cp2xlsx:
    def __init__(self, package: str) -> None:
        self.load_package(package)
        self.verify_package()
        self.package_name = self._index_['policyPackages'][0]['packageName']
        self.wb = xlsxwriter.Workbook(f'{self.package_name}.xlsx')
        self.init_styles()
        threads = []
        if self._net_:
            threads.append(Thread(target=self.gen_firewall_sheet))
        if self._nat_:
            threads.append(Thread(target=self.gen_nat_sheet))
        if self._tp_:
            threads.append(Thread(target=self.gen_tp_sheet))
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        # self.gen_firewall_sheet()
        # self.gen_nat_sheet()
        # self.gen_tp_sheet()
        self.wb.close()

    def get_filename(self) -> str:
        return self.wb.filename

    def verify_package(self) -> None:
        if self._index_ == None:
            print("Файл index.json не найден! Проверьте целостность архива.")
            input("Нажмите Enter для выхода.")
            quit()
        if self._objects_ == None:
            print("Файл objects.json не найден! Проверьте целостность архива.")
            input("Нажмите Enter для выхода.")
            quit()
        if self._net_ == None:
            print("Файл 'Network-Management server.json' не найден. Пропускаем таблицу Firewall...")
        if self._nat_ == None:
            print("Файл 'NAT-Management server.json' не найден. Пропускаем таблицу NAT...")
        if self._tp_ == None:
            print("Файл 'Threat Prevention-Management server.json' не найден. Пропускаем таблицу Threat Prevention...")

    def init_styles(self) -> None:
        default = {'valign': 'vcenter', 'border': True}
        self.style_default = self.wb.add_format(default)

        title = {**default, **{'font_size': '12', 'bold': True, 'bottom': True, 'align': 'center'}}
        self.style_title = self.wb.add_format(title)
        
        section = {**default, **{'bold': True, 'align': 'center', 'bg_color': 'yellow'}}
        self.style_section = self.wb.add_format(section)

        data = {**default, **{'text_wrap': True, 'align': 'left'}}
        self.style_data = self.wb.add_format(data)

        data_neg = {**data, **{'font_color': 'red', 'italic': True}}
        self.style_data_neg = self.wb.add_format(data_neg)

        data_dis = {**data, **{'bg_color': '#c8c8c8'}}
        self.style_data_dis = self.wb.add_format(data_dis)

        data_dis_neg = {**data_neg, **data_dis}
        self.style_data_dis_neg = self.wb.add_format(data_dis_neg)

    def load_package(self, package: str) -> None:
        self._index_ = None
        self._net_ = None
        self._gnet_ = None
        self._nat_ = None
        self._gwobj_ = None
        self._objects_ = None
        self._tp_ = None
        archive = tarfile.open(package, "r:gz")
        for file in archive:
            if fnmatch.fnmatch(file.name, 'index.json'):
                f = archive.extractfile(file)
                self._index_ = json.loads(f.readline())
                f.close()
                continue
            if fnmatch.fnmatch(file.name, '*Network-Global*.json'):
                print("Найдены глобальные правила.")
                continue
            if fnmatch.fnmatch(file.name, '*Network*.json'):
                f = archive.extractfile(file)
                self._net_ = json.loads(f.readline())
                f.close()
                continue
            if fnmatch.fnmatch(file.name, '*NAT*.json'):
                f = archive.extractfile(file)
                self._nat_ = json.loads(f.readline())
                f.close()
                continue
            if fnmatch.fnmatch(file.name, '*Threat Prevention*.json'):
                f = archive.extractfile(file)
                self._tp_ = json.loads(f.readline())
                f.close()
                continue
            if fnmatch.fnmatch(file.name, '*gateway_objects.json'):
                f = archive.extractfile(file)
                self._gwobj_ = json.loads(f.readline())
                f.close()
                continue
            if fnmatch.fnmatch(file.name, '*objects.json'):
                f = archive.extractfile(file)
                self._objects_ = json.loads(f.readline())
                f.close()
                continue
        archive.close()

    def find_obj_by_uid(self, uid: str) -> dict:
        for obj in self._objects_:
            if obj['uid'] == uid:
                return obj

    def decode_uid(self, uid: str) -> str:
        obj = self.find_obj_by_uid(uid)
        if not obj:
            return "!OBJECT NOT FOUND!"
        
        if 'host' in obj['type'] or 'gateway' in obj['type'] or 'cluster' in obj['type']:
            return f"{obj['name']} / {obj['ipv4-address']}"
        if obj['type'] == 'network':
            return f"{obj['name']} / {obj['subnet4']}/{obj['mask-length4']}"
        if obj['type'] == 'service-tcp':
            return f"tcp/{obj['port']}"
        if obj['type'] == 'service-udp':
            return f"udp/{obj['port']}"
        return obj['name']

    def decode_uid_list(self, uids: list) -> list:
        r = list()
        for el in uids:
            r.append(self.decode_uid(el))
        return r

    def list_to_str(self, l: list) -> str:
        if type(l) is not list:
            return l
        return '\n'.join(l)

    def expand_group(self, uids: list) -> list:
        if type(uids) is str:
            uids = [uids]
        result = list()
        for uid in uids:
            if type(uid) is not str:
                uid = uid['uid']
            obj = self.find_obj_by_uid(uid)
            if 'group' in obj['type']:
                result = result + self.expand_group(obj['members'])
            else:
                result = result + [uid]
        return result

    def gen_firewall_sheet(self) -> None:
        ws = self.wb.add_worksheet('Firewall')
        ws.set_column('A:A', 5)
        ws.set_column('B:B', 5)
        ws.set_column('C:C', 20)
        ws.set_column('D:E', 50)
        ws.set_column('F:G', 20)
        ws.set_column('H:I', 10)
        ws.set_column('J:J', 20)
        ws.set_column('K:K', 40)

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
        ws.write('K1', 'Comment', self.style_title)

        for i in range(len(self._net_)):
            row = i + 1
            style = self.style_data
            if self._net_[i]['type'] == "access-section":
                ws.merge_range(row, 0, row, 10, self._net_[i]['name'], self.style_section)
            else:
                if not self._net_[i]['enabled']:
                    style = self.style_data_dis
                ws.write(row, 0, self._net_[i]['rule-number'], style)
                try:
                    hits = self._net_[i]['hits']['value']
                except KeyError:
                    hits = ''
                ws.write(row, 1, hits, style)
                try:
                    name = self._net_[i]['name']
                except KeyError:
                    name = ''
                ws.write(row, 2, name, style)
                source = self.list_to_str(self.decode_uid_list(self.expand_group(self._net_[i]['source'])))
                if self._net_[i]['source-negate']:
                    ws.write(row, 3, source, self.style_data_dis_neg)
                else:
                    ws.write(row, 3, source, style)
                destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._net_[i]['destination'])))
                if self._net_[i]['destination-negate']:
                    ws.write(row, 4, destination, self.style_data_dis_neg)
                else:
                    ws.write(row, 4, destination, style)
                vpn = self.list_to_str(self.decode_uid_list(self.expand_group(self._net_[i]['vpn'])))
                ws.write(row, 5, vpn, style)
                service = self.list_to_str(self.decode_uid_list(self.expand_group(self._net_[i]['service'])))
                if self._net_[i]['service-negate']:
                    ws.write(row, 6, service, self.style_data_dis_neg)
                else:
                    ws.write(row, 6, service, style)
                action = self.list_to_str(self.decode_uid(self._net_[i]['action']))
                ws.write(row, 7, action, style)
                track = self.list_to_str(self.decode_uid(self._net_[i]['track']['type']))
                ws.write(row, 8, track, style)
                time = self.list_to_str(self.decode_uid_list(self.expand_group(self._net_[i]['time'])))
                ws.write(row, 9, time, style)
                ws.write(row, 10, self._net_[i]['comments'], style)

    def gen_nat_sheet(self) -> None:
        ws = self.wb.add_worksheet('NAT')
        ws.set_column('A:A', 5)
        ws.set_column('B:C', 50)
        ws.set_column('D:D', 20)
        ws.set_column('E:F', 50)
        ws.set_column('G:G', 20)
        ws.set_column('H:H', 40)

        ws.write('A1', '№', self.style_title)
        ws.write('B1', 'Original Source', self.style_title)
        ws.write('C1', 'Original Destination', self.style_title)
        ws.write('D1', 'Original Services', self.style_title)
        ws.write('E1', 'Translated Source', self.style_title)
        ws.write('F1', 'Translated Destination', self.style_title)
        ws.write('G1', 'Translated Services', self.style_title)
        ws.write('H1', 'Comments', self.style_title)

        for i in range(len(self._nat_)):
            row = i + 1
            style = self.style_data
            if self._nat_[i]['type'] == "nat-section":
                ws.merge_range(row, 0, row, 7, self._nat_[i]['name'], self.style_section)
            else:
                if not self._nat_[i]['enabled']:
                    style = self.style_data_dis
                ws.write(row, 0, self._nat_[i]['rule-number'], style)
                o_source = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['original-source'])))
                ws.write(row, 1, o_source, style)
                o_destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['original-destination'])))
                ws.write(row, 2, o_destination, style)
                o_service = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['original-service'])))
                ws.write(row, 3, o_service, style)
                t_source = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['translated-source'])))
                ws.write(row, 4, t_source, style)
                t_destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['translated-destination'])))
                ws.write(row, 5, t_destination, style)
                t_service = self.list_to_str(self.decode_uid_list(self.expand_group(self._nat_[i]['translated-service'])))
                ws.write(row, 6, t_service, style)
                ws.write(row, 7, self._nat_[i]['comments'], style)

    def gen_tp_sheet(self) -> None:
        ws = self.wb.add_worksheet('Threat Prevention')
        ws.set_column('A:A', 5)
        ws.set_column('B:C', 20)
        ws.set_column('D:E', 50)
        ws.set_column('F:F', 20)
        ws.set_column('G:I', 10)
        ws.set_column('J:J', 40)

        ws.write('A1', '№', self.style_title)
        ws.write('B1', 'Name', self.style_title)
        ws.write('C1', 'Protected Scope', self.style_title)
        ws.write('D1', 'Source', self.style_title)
        ws.write('E1', 'Destination', self.style_title)
        ws.write('F1', 'Protection/Site', self.style_title)
        ws.write('G1', 'Services', self.style_title)
        ws.write('H1', 'Action', self.style_title)
        ws.write('I1', 'Track', self.style_title)
        ws.write('J1', 'Comments', self.style_title)

        for i in range(len(self._tp_)):
            row = i + 1
            style = self.style_data
            if self._tp_[i]['type'] == "threat-section":
                ws.merge_range(row, 0, row, 9, self._tp_[i]['name'], self.style_section)
            else:
                if not self._tp_[i]['enabled']:
                    style = self.style_data_dis
                ws.write(row, 0, self._tp_[i]['rule-number'], style)
                try:
                    name = self._tp_[i]['name']
                except KeyError:
                    name = ''
                ws.write(row, 1, name, style)
                p_scope = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['protected-scope'])))
                if self._tp_[i]['protected-scope-negate']:
                    ws.write(row, 2, p_scope, self.style_data_dis_neg)
                else:
                    ws.write(row, 2, p_scope, style)
                source = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['source'])))
                if self._tp_[i]['source-negate']:
                    ws.write(row, 3, source, self.style_data_dis_neg)
                else:
                    ws.write(row, 3, source, style)
                destination = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['destination'])))
                if self._tp_[i]['destination-negate']:
                    ws.write(row, 4, destination, self.style_data_dis_neg)
                else:
                    ws.write(row, 4, destination, style)
                # p_site = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['protection-or-site'])))
                p_site = 'N/A'
                ws.write(row, 5, p_site, style)
                service = self.list_to_str(self.decode_uid_list(self.expand_group(self._tp_[i]['service'])))
                if self._tp_[i]['service-negate']:
                    ws.write(row, 6, service, self.style_data_dis_neg)
                else:
                    ws.write(row, 6, service, style)
                action = self.list_to_str(self.decode_uid(self._tp_[i]['action']))
                ws.write(row, 7, action, style)
                track = self.list_to_str(self.decode_uid(self._tp_[i]['track']))
                ws.write(row, 8, track, style)
                ws.write(row, 9, self._tp_[i]['comments'], style)
        

def main(args):
    print(f"cp2xlsx80 ver. {VERSION}")
    if len(args) > 1:
        start_time = time.perf_counter()
        cp = Cp2xlsx(args[1])
        end_time = time.perf_counter()
        file = cp.get_filename()
        print(f'Файл {file} преобразован за {end_time - start_time: 0.2f} секунды.')
        time.sleep(1)
    else:
        # Cp2xlsx('show_package-2022-10-03_15-44-34.tar.gz')
        # Cp2xlsx('show_package-2023-03-13_09-55-13.tar.gz')
        print("Использование: перетащите архив с выгрузкой из утилиты web_api_show_package.sh на этот файл.")
    input("Для выхода нажмите Enter")


if __name__ == "__main__":
    main(sys.argv)
