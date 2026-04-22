from class_define.object_definition import BaseEntity


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
        else:
            return (entity1, entity2)

