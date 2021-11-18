from binaryninja import Architecture
from .recc_arch import Recurso
from .recc_loader import RecursoLoader
from .callingConvention import ReccCallingConvention

Recurso.register()
Architecture['recurso'].register_calling_convention(ReccCallingConvention(Architecture['recurso'],'default'))
RecursoLoader.register()

