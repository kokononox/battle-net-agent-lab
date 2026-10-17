"""ONE observed pinned Download schema, not a vendor install-policy proof.

Reported metadata labels are the model input, NEVER imported success proof.
Every use must freshly match raw MD5/CKey + SHA256 + size + header + ordered
catalogue. No network, file IO, mutable configuration or ARM64 alias inference.
"""
from dataclasses import dataclass
@dataclass(frozen=True)
class Model:
    identity: str
    ckey: str
    sha256: str
    decoded_bytes: int
    format_version: int
    manifest_records: int
    tags: tuple

    def kind_for(self,name):
        return next((kind&~0x4000 for label,kind in self.tags if label==name),None)

PINNED_MODEL=Model(
    identity='wow-70391-download-observed-schema-1',
    ckey='5beff4cf8122da27a6788d9062c8d3c2',
    sha256='02f0ccb262e1a202e8beaf89ee9011a800b37f29cb34edbc36fe600204686ce1',
    decoded_bytes=74562151,format_version=1,manifest_records=2881619,
    tags=(
        ('Android', 1),
        ('IOS', 1),
        ('OSX', 1),
        ('PS5', 1),
        ('Web', 1),
        ('Windows', 1),
        ('XBSX', 1),
        ('arm64', 2),
        ('x86_32', 2),
        ('x86_64', 2),
        ('Alternate', 16384),
        ('HighRes', 16384),
        ('Talebound', 16384),
        ('deDE', 3),
        ('enUS', 3),
        ('esES', 3),
        ('esMX', 3),
        ('frFR', 3),
        ('itIT', 3),
        ('koKR', 3),
        ('ptBR', 3),
        ('ruRU', 3),
        ('zhCN', 3),
        ('zhTW', 3),
        ('CN', 4),
        ('EU', 4),
        ('KR', 4),
        ('TW', 4),
        ('US', 4),
        ('speech', 5),
        ('text', 5),
    ))

def for_ckey(ckey):
    return PINNED_MODEL if ckey==PINNED_MODEL.ckey else None
