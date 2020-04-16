import json

from pydantic import BaseModel


class Model(BaseModel):
    @classmethod
    def load(cls, data: dict):
        init = {}
        for k, v in data.items():
            if k in cls.schema()["properties"]:
                init[k] = v

        if init:
            return cls(**init)

        raise ValueError

    def to_json(self):
        return vars(self)
