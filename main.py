import fnmatch
import sys
import time
from threading import Thread
import tarfile
import json

import xlsxwriter

VERSION = '1.4'

class Cp2xlsx:
    def __init__(self, package: str, st: bool, eg: bool, sm: bool) -> None:
        self.st = st
        self.eg = eg
        self.sm = sm
        self.load_package(package)
        self.verify_package()
        self.package_name = self._index_['policyPackages'][0]['packageName']
        self.wb = xlsxwriter.Workbook(f'{self.package_name}.xlsx')
        self.init_styles()
        self._cached_groups_ = dict()
        self._cached_objects_ = dict()
        self._cached_uids_ = dict()
        self.run()
        self.wb.close()

    def run(self):
        g_fw_args   = ('Global FW', self._gnet_)
        l_fw_args   = ('Local FW', self._net_)
        nat_args    = ('NAT', self._nat_)
        tp_args     = ('TP', self._tp_)

        if self.st:
            if self.eg:
                self.gen_firewall_sheet(*g_fw_args)
            self.gen_firewall_sheet(*l_fw_args)
            self.gen_nat_sheet(*nat_args)
            self.gen_tp_sheet(*tp_args)
        else:
            threads = []
            if self._gnet_ and self.eg:
                threads.append(Thread(target=self.gen_firewall_sheet, args=(g_fw_args)))
            if self._net_:
                threads.append(Thread(target=self.gen_firewall_sheet, args=(l_fw_args)))
            if self._nat_:
                threads.append(Thread(target=self.gen_nat_sheet, args=(nat_args)))
            if self._tp_:
                threads.append(Thread(target=self.gen_tp_sheet, args=(tp_args)))

            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()


    def get_filename(self) -> str:
        """ Get xlsx file name

        Returns:
            str: file name
        """
        return self.wb.filename

    def verify_package(self) -> None:
        """ Check if all files from archive were loaded
        """
        if self._index_ == None:
            print("File index.json is not found! Check archive integrity.")
            input("Press Enter to exit.")
            quit()
        if self._objects_ == None:
            print("File *objects.json is not found! Check archive integrity.")
            input("Press Enter to exit.")
            quit()
        if self._gnet_ == None:
            print("File '*Network-Global*.json' is not found. Skipping Global Firewall table...")
        if self._net_ == None:
            print("File '*Network*.json' is not found. Skipping Firewall table...")
        if self._nat_ == None:
            print("File '*NAT*.json' is not found. Skipping NAT table...")
        if self._tp_ == None:
            print("File '*Threat Prevention*.json' is not found. Skipping Threat Prevention table...")
        if self._gwobj_ == None:
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

    def style_picker(self, enabled: bool = True, negated: bool = False) -> xlsxwriter.workbook.Format:
        """ Choose cells style

        Args:
            enabled (bool, optional): is rule enabled? Defaults to True.
            negated (bool, optional): is rule negated? Defaults to False.

        Returns:
            xlsxwriter.workbook.Format: style
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

    def find_obj_by_uid(self, uid: str) -> dict:
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

    def objects_to_str(self, uids: list | str) -> list:
        """ Represent objects in list with a string

        Args:
            uids (list): list of objects uids

        Returns:
            list: list of objects representations
        """
        if type(uids) is str:
            uids = [uids]
        result = list()
        for uid in uids:
            result.append(self.object_to_str(uid))
        return result

    def list_to_str(self, l: list) -> str:
        """ Convert list to string with new line

        Args:
            l (list): input list

        Returns:
            str
        """
        if type(l) is not list:
            return l
        return '\n'.join(l)

    def expand_group(self, uids: list | str) -> list:
        """ Recursively expand group object.

        Args:
            uids (list): list of objects uids

        Returns:
            list: list of uids of group members
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
            if 'group' in obj['type'] and self.sm:
                expanded = self.expand_group(obj['members'])
                result = result + expanded
                self._cached_groups_[uid] = expanded
            else:
                result = result + [uid]
        # return result without duplicates
        return list(dict.fromkeys(result))
    
    def write(self, ws: xlsxwriter.workbook.Worksheet, row: int, extra_row: int, col: int, extra_col: int, data: str, format: xlsxwriter.workbook.Format):
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

    def split_string(self, string: str) -> list:
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

    def gen_firewall_sheet(self, name: str, net_table: json) -> None:
        """Firewall page generation

        Args:
            name (str): page name
            net_table (json): net table object
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

    def gen_nat_sheet(self, name: str, nat_table: json) -> None:
        """ NAT page generation
        """
        ws = self.wb.add_worksheet(name)
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
        for entry in nat_table:
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
        for entry in tp_table:
            if entry['type'] == "threat-section":
                self.write(ws, row, 0, 0, 10, entry['name'], self.style_section)
            else:
                rule_number = str(entry['rule-number'])
                try:
                    name = entry['name']
                except KeyError:
                    name = ''
                p_scope = self.list_to_str(self.objects_to_str(self.expand_group(entry['protected-scope'])))
                source = self.list_to_str(self.objects_to_str(self.expand_group(entry['source'])))
                destination = self.list_to_str(self.objects_to_str(self.expand_group(entry['destination'])))
                p_site = 'N/A'
                service = self.list_to_str(self.objects_to_str(self.expand_group(entry['service'])))
                action = self.list_to_str(self.objects_to_str(entry['action']))
                track = self.list_to_str(self.objects_to_str(entry['track']))
                install_on = self.list_to_str(self.objects_to_str(self.expand_group(entry['install-on'])))
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
    import argparse
    
    def check_user_input(user_input: str) -> bool:
        user_input = user_input.lower()
        if user_input == "y":
            return True
        elif user_input == "n":
            return False
        else:
            return None

    print(f"cp2xlsx80 ver. {VERSION}")
    print("https://github.com/a5trocat/cp2xlsx")

    parser = argparse.ArgumentParser(prog="cp2xlsx", description="Convert Check Point policy package to xlsx")
    parser.add_argument("-st", "--single-thread", action="store_true", help="use single thread")
    eg_group = parser.add_mutually_exclusive_group()
    eg_group.add_argument("-eg", "--export-global", action="store_true", help="export global firewall rules")
    eg_group.add_argument("-neg", "--no-export-global", action="store_true")
    sm_group = parser.add_mutually_exclusive_group()
    sm_group.add_argument("-sm", "--show-members", action="store_true", help="show group members")
    sm_group.add_argument("-nsm", "--no-show-members", action="store_true")
    parser.add_argument("file", help="path to policy package file", )
    args = parser.parse_args()

    if args.export_global == args.no_export_global:
        eg = None
        while eg == None:
            eg = input("Would you like to export Global Firewall policy? [Y/n]: ")
            if eg == "":
                eg = True
            else:
                eg = check_user_input(eg)
    else:
        eg = args.export_global or not args.no_export_global

    if args.show_members == args.no_show_members:
        sm = None
        while sm == None:
            sm = input("Whould you like to show group members? [Y/n]: ")
            if sm == "":
                sm = True
            else:
                sm = check_user_input(sm)
    else:
        sm = args.show_members or not args.no_show_members

    start_time = time.perf_counter()
    cp = Cp2xlsx(args.file, args.single_thread, eg, sm)
    file = cp.get_filename()
    end_time = time.perf_counter()
    print(f'File {file} was converted in {end_time - start_time: 0.2f} seconds.')
    input("Press Enter to exit.")


if __name__ == "__main__":
    main(sys.argv)
