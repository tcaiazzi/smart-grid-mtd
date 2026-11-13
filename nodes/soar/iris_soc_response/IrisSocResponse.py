"""IrisSocResponse.py — the module's interface to IRIS: it registers the menu
entries and, when one is chosen, files the order as a task of the case. What an
entry orders is decided in orders.py; this file only talks to IRIS.

Runs inside IRIS, against IRIS's own module interface and data model, as IRIS's
own modules do. The entries run in IRIS's app, within the analyst's request
(run_asynchronously=False), not in its worker: IRIS v2.4.29's worker does not
load the secret it verifies queued hooks with, so every queued entry fails
there. Run in the request, the order is filed at once and names the analyst.
"""

import iris_interface.IrisInterfaceStatus as InterfaceStatus
from iris_interface.IrisModuleInterface import IrisModuleInterface, IrisModuleTypes

import iris_soc_response.IrisSocResponseConfig as conf
from iris_soc_response import orders

TODO = 1  # IRIS's "To do" task state


class IrisSocResponse(IrisModuleInterface):
    _module_name = conf.module_name
    _module_description = conf.module_description
    _interface_version = conf.interface_version
    _module_version = conf.module_version
    _pipeline_support = conf.pipeline_support
    _pipeline_info = conf.pipeline_info
    _module_configuration = conf.module_configuration
    _module_type = IrisModuleTypes.module_processor

    def register_hooks(self, module_id: int):
        for hook, entry in orders.ENTRIES:
            status = self.register_to_hook(
                module_id, iris_hook_name=hook, manual_hook_name=entry, run_asynchronously=False
            )
            if status.is_failure():
                self.log.error(f"could not add {entry!r}: {status.get_message()}")

    def hooks_handler(self, hook_name: str, hook_ui_name: str, data: any):
        if self._dict_conf.get("orders_enabled") is False:
            return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))
        # IRIS's data model and session, imported here: they exist only inside IRIS.
        from app.datamgmt.case.case_tasks_db import add_task
        from app.models import CaseTasks
        from flask_login import current_user

        for obj in data:
            if hook_name == "on_manual_trigger_task":
                filed = orders.order_of(hook_ui_name, obj.task_tags)
                caseid = obj.task_case_id
            else:
                filed = orders.order_of(hook_ui_name)
                caseid = obj.case_id
            if filed is None:
                self.log.warning(f"{hook_ui_name!r} does not apply to this object: no order filed")
                continue
            title, tags = filed
            task = CaseTasks()
            task.task_title = title
            task.task_description = (
                f"Filed by {current_user.user} from IRIS's menu; the SOC carries it out and "
                "closes it."
            )
            task.task_status_id = TODO
            task.task_tags = ",".join(tags + [f"by:{current_user.user}"])
            add_task(task, [], current_user.id, caseid)
            self.log.info(f"{current_user.user} filed {title!r} in case {caseid}")
        return InterfaceStatus.I2Success(data=data, logs=list(self.message_queue))
