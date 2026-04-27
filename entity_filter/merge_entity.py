from class_define.object_definition import BaseEntity, ProcessEntity


class EntityMerger:
    @staticmethod
    def merge_and_update(entity1: BaseEntity, entity2: BaseEntity):
        if entity1.get_id() == entity2.get_id():
            # if entity1.event_id != entity2.event_id:
            #     return (entity1, entity2)
            for key, value in entity1.__dict__.items():
                if key != "event_id":
                    if value is None:
                        setattr(entity1, key, getattr(entity2, key))
            return entity1

        # Merge ProcessEntity instances that share the same command_hash.
        # command_hash already encodes process-name/extension semantics.
        if (
            isinstance(entity1, ProcessEntity)
            and isinstance(entity2, ProcessEntity)
            and entity1.command_hash
            and entity1.command_hash == entity2.command_hash
        ):
            # Merge: guid and pid of entity1 are preserved; fill other empty fields from entity2
            preserved_guid = entity1.guid
            preserved_pid = entity1.pid
            for key, value in entity1.__dict__.items():
                if key not in ("event_id", "guid", "pid"):
                    if not value:
                        setattr(entity1, key, getattr(entity2, key))
            entity1.guid = preserved_guid
            entity1.pid = preserved_pid
            print(f"Merged ProcessEntity with command_hash {entity1.command_hash}: {entity1.get_id()} and {entity2.get_id()}")
            return entity1

        return (entity1, entity2)

