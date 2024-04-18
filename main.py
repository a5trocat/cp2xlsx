import argparse
import fnmatch
import sys
import time
from pathlib import Path
import tarfile
import json

import xlsxwriter
from tqdm import tqdm

VERSION = '1.7.2'

class Cp2xlsx:
    def __init__(self, package: str, eg: bool, sm: bool, sg: str) -> None:
        self.eg = eg
        self.sm = sm
        self.sg = sg
        self.load_package(package)
        self.verify_package()
        self.package_name = self._index_['policyPackages'][0]['packageName']
        self.wb = xlsxwriter.Workbook(f'{self.package_name}.xlsx')
        self.init_styles()
        self._cached_groups_ = {}
        self._cached_objects_ = {}
        self._cached_uids_ = {}
        self.run()


    def run(self):
        if self.eg:
            if len(self._gnet_) == 0:
                print("Global FW is empty.")
            else:
                self.gen_firewall_sheet('Global FW', self._gnet_)
        if len(self._net_) == 0:
            print("Local FW is empty.")
        else:
            self.gen_firewall_sheet('Local FW', self._net_)
        if len(self._nat_) == 0:
            print("NAT is empty.")
        else:
            self.gen_nat_sheet('NAT table', self._nat_)
        if len(self._tp_) == 0:
            print("TP is empty")
        else:
            self.gen_tp_sheet('TP table', self._tp_)
        if self.sg != "no":
            self.save_groups_to_files()
        self.wb.close()


    def save_groups_to_files(self):
        # create dir for txt files. empty dir if it exists
        dir_path = Path(f"./{self.package_name}")
        if dir_path.exists():
            if dir_path.is_dir():
                for file in dir_path.iterdir():
                    file.unlink()
            else:
                dir_path.unlink()
        else:
            dir_path.mkdir()

        groups: list[dict] = []
        groups_to_iterate = self._cached_groups_ if self.sg == "policy" else self._objects_
        for obj in tqdm(groups_to_iterate, desc="Parsing groups", ncols=100, bar_format='{desc}\t: |{bar}| {n_fmt:5}/{total_fmt:5} [{elapsed_s:.2f}s]'):
            if self.sg == "all":
                obj_decoded = self.find_obj_by_uid(obj["uid"])
            else:
                obj_decoded = self.find_obj_by_uid(obj)
            if 'group' in obj_decoded['type']:
                group = {}
                group["name"] = obj_decoded["name"]
                group["members"] = []
                for group_member in obj_decoded["members"]:
                    member = self.object_to_str(group_member["uid"])
                    group["members"].append(member)
                groups.append(group)

        for group in tqdm(groups, desc="Saving groups", ncols=100, bar_format='{desc}\t: |{bar}| {n_fmt:5}/{total_fmt:5} [{elapsed_s:.2f}s]'):
            file_path = dir_path / f"{group["name"]}.txt"
            with file_path.open("w", encoding="UTF-8") as file:
                for member in group["members"]:
                    file.write(member + "\n")


    def get_filename(self) -> str:
        """ Get xlsx file name

        Returns:
            str: file name
        """
        return self.wb.filename


    def verify_package(self) -> None:
        """ Check if all files from archive were loaded
        """
        if self._index_ is None:
            print("File index.json is not found! Check archive integrity.")
            input("Press Enter to exit.")
            sys.exit()
        if self._objects_ is None:
            print("File *objects.json is not found! Check archive integrity.")
            input("Press Enter to exit.")
            sys.exit()
        if self._gnet_ is None:
            print("File '*Network-Global*.json' is not found. Skipping Global Firewall table...")
        if self._net_ is None:
            print("File '*Network*.json' is not found. Skipping Firewall table...")
        if self._nat_ is None:
            print("File '*NAT*.json' is not found. Skipping NAT table...")
        if self._tp_ is None:
            print("File '*Threat Prevention*.json' is not found. Skipping Threat Prevention table...")
        if self._gwobj_ is None:
            print("File '*gateway_objects.json' is not found.")


    def init_styles(self) -> None:
        """ Init workbook styles
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

        data_temp = {**data, **{'bg_color': '#ffe994'}}
        self.style_data_temp = self.wb.add_format(data_temp)

        data_temp_neg = {**data_neg, **data_temp}
        self.style_data_temp_neg = self.wb.add_format(data_temp_neg)


    def get_style(self, enabled: bool=True, temp: bool=False, src_neg: bool=False, dst_neg: bool=False, serv_neg: bool=False, ps_neg: bool=False) -> dict:
        """Get style for each cell in row

        Args:
            enabled (bool, optional): Is rule enabled?. Defaults to True.
            temp (bool, optional): Is rule temp?. Defaults to False.
            src_neg (bool, optional): Is source negated?. Defaults to False.
            dst_neg (bool, optional): Is destination negated?. Defaults to False.
            serv_neg (bool, optional): Is service negated?. Defaults to False.
            ps_neg (bool, optional): Is protection scope negated?. Defaults to False.

        Returns:
            dict: Dict of styles for cells
        """
        if enabled:
            if temp:
                default = self.style_data_temp
                src = self.style_data_temp_neg if src_neg else default
                dst = self.style_data_temp_neg if dst_neg else default
                serv = self.style_data_temp_neg if serv_neg else default
                ps = self.style_data_temp_neg if ps_neg else default
            else:
                default = self.style_data
                src = self.style_data_neg if src_neg else default
                dst = self.style_data_neg if dst_neg else default
                serv = self.style_data_neg if serv_neg else default
                ps = self.style_data_neg if ps_neg else default
        else: # if rule is disabled
            default = self.style_data_dis
            src = self.style_data_dis_neg if src_neg else default
            dst = self.style_data_dis_neg if dst_neg else default
            serv = self.style_data_dis_neg if serv_neg else default
            ps = self.style_data_dis_neg if ps_neg else default
        return {"default": default, "source": src, "destination": dst, "service": serv, "protection-scope": ps}


    def load_package(self, package: str) -> None:
        """ Open policy package archive and load JSONs into memory

        Args:
            package (str): archive path
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
                elif fnmatch.fnmatch(file.name, '*Network-Global*.json'):
                    with archive.extractfile(file) as f:
                        self._gnet_ = json.loads(f.readline())
                elif fnmatch.fnmatch(file.name, '*Network*.json'):
                    with archive.extractfile(file) as f:
                        self._net_ = json.loads(f.readline())
                elif fnmatch.fnmatch(file.name, '*NAT*.json'):
                    with archive.extractfile(file) as f:
                        self._nat_ = json.loads(f.readline())
                elif fnmatch.fnmatch(file.name, '*Threat Prevention*.json'):
                    with archive.extractfile(file) as f:
                        self._tp_ = json.loads(f.readline())
                elif fnmatch.fnmatch(file.name, '*gateway_objects.json'):
                    with archive.extractfile(file) as f:
                        self._gwobj_ = json.loads(f.readline())
                elif fnmatch.fnmatch(file.name, '*objects.json'):
                    with archive.extractfile(file) as f:
                        self._objects_ = json.loads(f.readline())


    def find_obj_by_uid(self, uid: str) -> dict | None:
        """ Find object by uid

        Args:
            uid (str): object uid

        Returns:
            dict: object
        """
        if uid in self._cached_uids_:
            return self._cached_uids_[uid]
        for obj in self._objects_:
            if obj['uid'] == uid:
                self._cached_uids_[uid] = obj
                return obj
        return None


    def object_to_str(self, uid: str) -> str:
        """ Represent object with a string

        Args:
            uid (str): object uid

        Returns:
            str: object representation
        """
        if uid in self._cached_objects_:
            return self._cached_objects_[uid]
        obj = self.find_obj_by_uid(uid)
        if not obj:
            result = "!OBJECT NOT FOUND!"
            self._cached_objects_[uid] = result
            return result

        if obj['type'] in ['host', 'simple-gateway', 'simple-cluster']:
            result = f"{obj['name']} / {obj['ipv4-address']}"
        elif obj['type'] == 'network':
            result = f"{obj['name']} / {obj['subnet4']}/{obj['mask-length4']}"
        elif obj['type'] == 'service-tcp':
            result = f"tcp/{obj['port']}"
        elif obj['type'] == 'service-udp':
            result = f"udp/{obj['port']}"
        elif obj['type'] == 'CpmiAnyObject':
            result = "Any"
        elif obj['type'] == 'time':
            if obj['end-never']:
                result = obj['name']
                if obj['comments']:
                    result += f' ({obj['comments']})'
            else:
                result = f"{obj['end']['iso-8601'][:-3].replace('T', ' ')}"
            
        else:
            result = obj['name']

        self._cached_objects_[uid] = result
        return result


    def objects_to_str(self, uids: list | str) -> list:
        """ Represent objects in list with a string

        Args:
            uids (list): list of objects uids

        Returns:
            list: list of objects representations
        """
        if isinstance(uids, str):
            uids = [uids]
        result = []
        for uid in uids:
            result.append(self.object_to_str(uid))
        return result


    @staticmethod
    def list_to_str(l: list) -> str:
        """ Convert list to string with new line

        Args:
            l (list): input list

        Returns:
            str
        """
        if not isinstance(l, list):
            return l
        return '\n'.join(l)


    def expand_group(self, uids: list | str) -> list[str]:
        """ Recursively expand group object.

        Args:
            uids (list): list of objects uids

        Returns:
            list: list of uids of group members
        """
        if isinstance(uids, str):
            uids = [uids]
        result = []
        for uid in uids:
            if not isinstance(uid, str):
                uid = uid['uid']
            if uid in self._cached_groups_:
                if self.sm:
                    result = result + self._cached_groups_[uid]
                else:
                    result = result + [uid]
                continue
            obj = self.find_obj_by_uid(uid)
            if 'group' in obj['type']:
                expanded = self.expand_group(obj['members'])
                self._cached_groups_[uid] = expanded
                if self.sm:
                    result = result + expanded
            result = result + [uid]
        # return result without duplicates
        return list(dict.fromkeys(result))


    @staticmethod
    def write(ws: xlsxwriter.workbook.Worksheet, row: int, extra_row: int, col: int, extra_col: int, data: str, format: xlsxwriter.workbook.Format):
        """ Single function for xlsxwriter merge_range write.

        Args:
            ws (xlsxwriter.workbook.Worksheet): worksheet
            row (int): row
            extra_row (int): merge with extra rows
            col (int): column
            extra_col (int): merge with extra columns
            data (str): data
            format (xlsxwriter.workbook.Format): format
        """
        if extra_row or extra_col:
            ws.merge_range(row, col, row + extra_row, col + extra_col, data, format)
        else:
            ws.write(row, col, data, format)


    @staticmethod
    def split_string(string: str) -> list:
        """ Split string with len() > 32767 to comply with xlsx cell's max len

        Args:
            string (str): input string

        Returns:
            list: list of strings
        """
        result = []
        while len(string) > 32767:
            last_new_line = string[:32767].rindex('\n')
            result.append(string[:last_new_line])
            string = string[last_new_line+1:]
        result.append(string)
        return result


    @staticmethod
    def format_hits(num: int) -> str:
        ds = [(1e15, 'Q'), (1e12, 'T'), (1e9, 'B'), (1e6, 'M'), (1e3, 'K')]
        for d in ds:
            head = num / d[0]
            if head > 1:
                return f"{head:.0f}{d[1]}"
        return str(num)


    def gen_firewall_sheet(self, name: str, net_table: json) -> None:
        """Firewall page generation

        Args:
            name (str): page name
            net_table (json): net table object
        """

        ws = self.wb.add_worksheet(name)
        ws.outline_settings(True, False)

        ws.set_column('A:A', 5)
        ws.set_column('B:B', 7)
        ws.set_column('C:C', 20)
        ws.set_column('D:E', 40)
        ws.set_column('F:F', 15)
        ws.set_column('G:G', 20)
        ws.set_column('H:I', 10)
        ws.set_column('J:J', 20)
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
        for entry in tqdm(net_table, desc=name, ncols=100, bar_format='{desc}\t: |{bar}| {n_fmt:5}/{total_fmt:5} [{elapsed_s:.2f}s]'):
            if entry['type'] == "place-holder":
                self.write(ws, row, 0, 0, 0, str(entry['rule-number']), self.style_placeholder)
                self.write(ws, row, 0, 1, 10, entry['name'], self.style_placeholder)
            elif entry['type'] == "access-section":
                self.write(ws, row, 0, 0, 11, entry['name'], self.style_section)
            else:
                rule_number = str(entry['rule-number'])
                hits = entry.get('hits')
                if hits:
                    hits = self.format_hits(hits['value'])

                name = entry.get('name', '')
                source = self.split_string(self.list_to_str(self.objects_to_str(self.expand_group(entry['source']))))
                s_trunkated_len = len(source)
                destination = self.split_string(self.list_to_str(self.objects_to_str(self.expand_group(entry['destination']))))
                d_trunkated_len = len(destination)
                extra_rows = max(s_trunkated_len, d_trunkated_len) - 1
                vpn = self.list_to_str(self.objects_to_str(self.expand_group(entry['vpn'])))
                service = self.list_to_str(self.objects_to_str(self.expand_group(entry['service'])))
                action = self.list_to_str(self.objects_to_str(entry['action']))
                track = self.list_to_str(self.objects_to_str(entry['track']['type']))
                time = self.list_to_str(self.objects_to_str(self.expand_group(entry['time'])))
                install_on = self.list_to_str(self.objects_to_str(self.expand_group(entry['install-on'])))
                comments = entry['comments']

                style = self.get_style(
                    enabled=entry['enabled'],
                    temp=True if time != "Any" else False,
                    src_neg=entry['source-negate'],
                    dst_neg=entry['destination-negate'],
                    serv_neg=entry['service-negate']
                    )

                self.write(ws, row, extra_rows, 0, 0, rule_number, style['default'])
                self.write(ws, row, extra_rows, 1, 0, hits, style['default'])
                self.write(ws, row, extra_rows, 2, 0, name, style['default'])
                row_for_data = extra_rows // s_trunkated_len
                s_rows_remain = extra_rows
                for i in range(s_trunkated_len):
                    if s_rows_remain < row_for_data:
                        row_for_data = s_rows_remain
                    self.write(ws, row+i, row_for_data, 3, 0, source[i], style['source'])
                    s_rows_remain = s_rows_remain - row_for_data
                row_for_data = extra_rows // d_trunkated_len
                d_rows_remain = extra_rows
                for i in range(d_trunkated_len):
                    if d_rows_remain < row_for_data:
                        row_for_data = d_rows_remain
                    self.write(ws, row+i, row_for_data, 4, 0, destination[i], style['destination'])
                    d_rows_remain = d_rows_remain - row_for_data
                self.write(ws, row, extra_rows, 5, 0, vpn, style['default'])
                self.write(ws, row, extra_rows, 6, 0, service, style['service'])
                self.write(ws, row, extra_rows, 7, 0, action, style['default'])
                self.write(ws, row, extra_rows, 8, 0, track, style['default'])
                self.write(ws, row, extra_rows, 9, 0, time, style['default'])
                self.write(ws, row, extra_rows, 10, 0, install_on, style['default'])
                self.write(ws, row, extra_rows, 11, 0, comments, style['default'])
                for i in range(extra_rows + 1):
                    ws.set_row(row + i, None, None, {'level': 1, 'hidden': False})
                row = row + extra_rows
            row = row + 1


    def gen_nat_sheet(self, name: str, nat_table: json) -> None:
        """ NAT page generation
        """
        ws = self.wb.add_worksheet(name)
        ws.outline_settings(True, False)

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
        for entry in tqdm(nat_table, desc=name, ncols=100, bar_format='{desc}\t: |{bar}| {n_fmt:5}/{total_fmt:5} [{elapsed_s:.2f}s]'):
            if entry['type'] == "nat-section":
                self.write(ws, row, 0, 0, 8, entry['name'], self.style_section)
            else:
                rule_number = str(entry['rule-number'])
                o_source = self.list_to_str(self.objects_to_str(self.expand_group(entry['original-source'])))
                o_destination = self.list_to_str(self.objects_to_str(self.expand_group(entry['original-destination'])))
                o_service = self.list_to_str(self.objects_to_str(self.expand_group(entry['original-service'])))
                t_source = self.list_to_str(self.objects_to_str(self.expand_group(entry['translated-source'])))
                t_destination = self.list_to_str(self.objects_to_str(self.expand_group(entry['translated-destination'])))
                t_service = self.list_to_str(self.objects_to_str(self.expand_group(entry['translated-service'])))
                install_on = self.list_to_str(self.objects_to_str(self.expand_group(entry['install-on'])))
                comments = entry['comments']
                style = self.get_style(enabled=entry['enabled'])

                self.write(ws, row, 0, 0, 0, rule_number, style['default'])
                self.write(ws, row, 0, 1, 0, o_source, style['default'])
                self.write(ws, row, 0, 2, 0, o_destination, style['default'])
                self.write(ws, row, 0, 3, 0, o_service, style['default'])
                self.write(ws, row, 0, 4, 0, t_source, style['default'])
                self.write(ws, row, 0, 5, 0, t_destination, style['default'])
                self.write(ws, row, 0, 6, 0, t_service, style['default'])
                self.write(ws, row, 0, 7, 0, install_on, style['default'])
                self.write(ws, row, 0, 8, 0, comments, style['default'])
                ws.set_row(row, None, None, {'level': 1, 'hidden': False})
            row = row + 1


    def gen_tp_sheet(self, name: str, tp_table: json) -> None:
        """ Threat prevention page generation
        """
        ws = self.wb.add_worksheet(name)
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
        for entry in tqdm(tp_table, desc=name, ncols=100, bar_format='{desc}\t: |{bar}| {n_fmt:5}/{total_fmt:5} [{elapsed_s:.2f}s]'):
            if entry['type'] == "threat-section":
                self.write(ws, row, 0, 0, 10, entry['name'], self.style_section)
                row = row + 1
                continue
            elif entry['type'] == "threat-rule":
                rule_number = str(entry['rule-number'])
                p_site = 'N/A'
            elif entry['type'] == "threat-exception":
                rule_number = 'E' + str(entry['exception-number'])
                p_site = self.list_to_str(self.objects_to_str(self.expand_group(entry['protection-or-site'])))
            name = entry.get('name', '')
            p_scope = self.list_to_str(self.objects_to_str(self.expand_group(entry['protected-scope'])))
            source = self.list_to_str(self.objects_to_str(self.expand_group(entry['source'])))
            destination = self.list_to_str(self.objects_to_str(self.expand_group(entry['destination'])))
            service = self.list_to_str(self.objects_to_str(self.expand_group(entry['service'])))
            action = self.list_to_str(self.objects_to_str(entry['action']))
            track = self.list_to_str(self.objects_to_str(entry['track']))
            install_on = self.list_to_str(self.objects_to_str(self.expand_group(entry['install-on'])))
            comments = entry['comments']
            style = self.get_style(
                enabled=entry['enabled'],
                src_neg=entry['source-negate'],
                dst_neg=entry['destination-negate'],
                serv_neg=entry['service-negate'],
                ps_neg=entry['protected-scope-negate']
                )

            self.write(ws, row, 0, 0, 0, rule_number, style['default'])
            self.write(ws, row, 0, 1, 0, name, style['default'])
            self.write(ws, row, 0, 2, 0, p_scope, style['protection-scope'])
            self.write(ws, row, 0, 3, 0, source, style['source'])
            self.write(ws, row, 0, 4, 0, destination, style['destination'])
            self.write(ws, row, 0, 5, 0, p_site, style['default'])
            self.write(ws, row, 0, 6, 0, service, style['service'])
            self.write(ws, row, 0, 7, 0, action, style['default'])
            self.write(ws, row, 0, 8, 0, track, style['default'])
            self.write(ws, row, 0, 9, 0, install_on, style['default'])
            self.write(ws, row, 0, 10, 0, comments, style['default'])
            row = row + 1


def main(args):
    def check_user_input(user_input: str) -> bool:
        user_input = user_input.lower()
        if user_input == "y":
            return True
        if user_input == "n":
            return False
        return None

    print(f"cp2xlsx80 ver. {VERSION}")
    print("https://github.com/a5trocat/cp2xlsx")

    parser = argparse.ArgumentParser(prog="cp2xlsx", description="Convert Check Point policy package to xlsx", formatter_class=argparse.RawTextHelpFormatter)
    eg_group = parser.add_mutually_exclusive_group()
    eg_group.add_argument("-eg", "--export-global", action="store_true", help="export global firewall rules")
    eg_group.add_argument("-neg", "--no-export-global", action="store_true")
    sm_group = parser.add_mutually_exclusive_group()
    sm_group.add_argument("-sm", "--show-members", action="store_true", help="show group members")
    sm_group.add_argument("-nsm", "--no-show-members", action="store_true")
    parser.add_argument("-sg", "--save-groups", choices=["no", "policy", "all"], required=False, default=None, help="save group members to files (default: no)\npolicy: save groups only used in the policy\nall: save all groups")
    parser.add_argument("file", help="path to policy package file", )
    args = parser.parse_args()

    if args.export_global == args.no_export_global:
        eg = None
        while eg is None:
            eg = input("Would you like to export Global Firewall policy? [Y/n]: ")
            if eg == "":
                eg = True
            else:
                eg = check_user_input(eg)
    else:
        eg = args.export_global or not args.no_export_global

    if args.show_members == args.no_show_members:
        sm = None
        while sm is None:
            sm = input("Would you like to show group members? [Y/n]: ")
            if sm == "":
                sm = True
            else:
                sm = check_user_input(sm)
    else:
        sm = args.show_members or not args.no_show_members

    if not args.save_groups:
        sg = input("Would you like to save group members to file? [NO/policy/all]: ")
        sg = sg.lower()
        if sg not in ["policy", "all"]:
            sg = "no"
    else:
        sg = args.save_groups

    start_time = time.perf_counter()
    cp = Cp2xlsx(args.file, eg, sm, sg)
    file = cp.get_filename()
    end_time = time.perf_counter()
    print(f'File {file} was converted in {end_time - start_time: 0.2f} seconds.')
    input("Press Enter to exit.")


if __name__ == "__main__":
    main(sys.argv)
