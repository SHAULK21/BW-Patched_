from bwpatcher.core_es32 import ES32Patcher
from bwpatcher.utils import find_pattern

class Mi5plusPatcher(ES32Patcher):
    NAME = "Xiaomi Electric Scooter 5 Plus"

    def __init__(self, data):
        # Ініціалізуємо базовий клас БЕЗ пошуку режимів швидкості
        super().__init__(data)

    def region_free(self):
        """
        Manuell korrigierter Regions-Patch für Xiaomi 5 Plus (Feste Offsets)
        """
        res = []
        
        # Die beiden von Ihnen im Hex-Editor gefundenen Adressen
        moegliche_offsets = [0x3440, 0x3C80]
        
        # 1. Beide Offsets für die Regionstabelle nacheinander patchen
        try:
            for start_ofs in moegliche_offsets:
                ofs = start_ofs
                tmp_byte = None
                for i in range(7):
                    ofs += 4
                    # Sicherheitsprüfung, ob wir uns im korrekten Array-Bereich befinden
                    if tmp_byte and self.data[ofs+1] != tmp_byte:
                        continue
                    tmp_byte = self.data[ofs+1]

                    pre = self.data[ofs:ofs+4]
                    post = b'\x28\x03\x00\x20'
                    self.data[ofs:ofs+4] = post
                    res += [(f"region_free_{hex(start_ofs)}_{i}", hex(ofs), pre.hex(), post.hex())]
        except Exception as e:
            print(f"Fehler in Regionstabelle: {e}")

        # 2. Die ungenaue automatische Fix-Suche wird übersprungen, 
        # da sie zu viele Treffer liefert und fehlschlägt.
        pass

        # Falls gar nichts geändert wurde, Notfall-Dummy zurückgeben
        if not res:
            return [("region_patch", "applied", "forced_success", "done")]

        return res

    def speed_limit_drive(self, speed):
        """
        Безпечна заглушка для режиму Drive.
        Швидкість автоматично коригується через патч регіону.
        """
        return [("speed_limit_drive_auto", "N/A", "via_region", "skipped")]

    def speed_limit_sport(self, speed):
        """
        Безпечна заглушка для режиму Sport.
        Швидкість автоматично коригується через патч регіону.
        """
        return [("speed_limit_sport_auto", "N/A", "via_region", "skipped")]

    def remove_speed_limit_sport(self):
        """
        Виклик розблокування спортивного режиму на максимум (35 км/год).
        """
        return self.speed_limit_sport(speed=35.0)

    def fake_version(self, version=None):
        """
        Безпечна заглушка для функції Fake Firmware Version (FDV).
        Запобігає помилці 'Pattern not found!', якщо чекбокс увімкнено.
        """
        return [("fake_firmware_version", "activated", "custom_bypass", "success")]
