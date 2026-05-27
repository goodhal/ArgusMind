"""Neo4j 数据仓库"""
from __future__ import annotations

from typing import Dict, List, Optional

from src.storage.neo4j.client import Neo4jClient


def _normalize_node_spec(node_spec: Dict) -> Dict:
    """与图谱 JSON 对齐：elementId 可作为 id（elementId）的别名。"""
    ns = dict(node_spec)
    if ns.get("id") in (None, ""):
        ns.pop("id", None)
    if "id" not in ns and "elementId" in ns:
        ev = ns.get("elementId")
        if ev not in (None, ""):
            ns["id"] = ev
    return ns


class Neo4jRepository:
    """Neo4j 数据仓库"""
    
    def __init__(self, client: Neo4jClient):
        self.client = client
    
    def merge_node(
        self,
        label: str,
        match_properties: Dict,
        extra_properties: Optional[Dict] = None,
    ) -> Dict:
        """
        幂等创建节点：以 `match_properties` 为唯一键 MERGE，若首次创建则写入 `extra_properties`。

        Args:
            label: 节点标签
            match_properties: 作为唯一匹配条件的属性（如 name/task_id 等）
            extra_properties: 仅在节点首次创建时写入（通过 ON CREATE SET）

        Returns:
            节点属性字典，附带 elementId、labels；若失败返回空字典。
        """
        if not match_properties:
            raise ValueError("merge_node 要求至少传入一个匹配属性")

        match_str = ", ".join(f"{k}: $match_{k}" for k in match_properties.keys())
        params: Dict = {f"match_{k}": v for k, v in match_properties.items()}

        create_clause = ""
        if extra_properties:
            sets = []
            for k, v in extra_properties.items():
                if k in match_properties:
                    continue
                sets.append(f"n.{k} = $extra_{k}")
                params[f"extra_{k}"] = v
            if sets:
                create_clause = "ON CREATE SET " + ", ".join(sets)

        query = f"""
        MERGE (n:{label} {{{match_str}}})
        {create_clause}
        RETURN n AS n, elementId(n) AS elementId, labels(n) AS labels
        """
        records = self.client.execute_write(query, params)
        if not records:
            return {}
        record = records[0]
        out = dict(record["n"])
        out["elementId"] = record["elementId"]
        out["labels"] = list(record["labels"] or [])
        return out

    def find_node(
        self,
        label: str,
        match_properties: Dict,
    ) -> Dict:
        """按标签 + 属性查找节点；若不存在返回空字典。"""
        if not match_properties:
            raise ValueError("find_node 要求至少传入一个匹配属性")
        match_str = ", ".join(f"{k}: $m_{k}" for k in match_properties.keys())
        params = {f"m_{k}": v for k, v in match_properties.items()}
        query = f"""
        MATCH (n:{label} {{{match_str}}})
        RETURN n AS n, elementId(n) AS elementId, labels(n) AS labels
        LIMIT 1
        """
        records = self.client.execute_read(query, params)
        if not records:
            return {}
        record = records[0]
        out = dict(record["n"])
        out["elementId"] = record["elementId"]
        out["labels"] = list(record["labels"] or [])
        return out

    def create_node(self, label: str, properties: Optional[Dict] = None) -> Dict:
        """
        通用：创建指定标签的节点
        
        Args:
            label: 节点标签（如 "Project", "Task", "File"）
            properties: 节点属性字典，可为 None 表示无属性
            
        Returns:
            节点业务属性字典，并附加 Neo4j 的 elementId、labels（字符串列表）；
            失败则返回空字典。
            
        Example:
            create_node("Project", {"name": "myapp", "path": "/path", "task_id": "t1", "created_at": "..."})
            create_node("Tag", {"name": "urgent"})
        """
        props = dict(properties) if properties else {}
        if not props:
            query = f"""
            CREATE (n:{label})
            RETURN n AS n, elementId(n) AS elementId, labels(n) AS labels
            """
            parameters = {}
        else:
            props_str = ", ".join([f"{k}: ${k}" for k in props.keys()])
            query = f"""
            CREATE (n:{label} {{{props_str}}})
            RETURN n AS n, elementId(n) AS elementId, labels(n) AS labels
            """
            parameters = props
        records = self.client.execute_write(query, parameters)
        if records:
            record = records[0]
            out = dict(record["n"])
            out["elementId"] = record["elementId"]
            out["labels"] = list(record["labels"] or [])
            return out
        return {}
    
    def create_relationship(
        self,
        from_node: Dict,
        to_node: Dict,
        relationship_type: str,
        relationship_properties: Optional[Dict] = None,
        auto_create_nodes: bool = True
    ) -> Dict:
        """
        创建节点之间的关系，如果节点不存在则自动创建
        
        Args:
            from_node: 起始节点规格
                       - 通过ID匹配: {"id": "element_id"}
                       - 通过标签和属性匹配/创建: {"label": "Label", "key": "value", ...}
                       - 创建新节点: {"label": "Label", "key": "value", ...} (auto_create_nodes=True时)
            to_node: 目标节点规格，格式同上
            relationship_type: 关系类型（如 "BELONGS_TO", "DEPENDS_ON" 等）
            relationship_properties: 可选的关系属性字典
            auto_create_nodes: 如果节点不存在是否自动创建（默认True）
            
        Returns:
            创建的关系数据字典，如果失败则返回空字典
            
        Example:
            # 自动创建节点并建立关系
            create_relationship(
                {"label": "Project", "name": "project1", "path": "/path/to/project"},
                {"label": "Task", "task_id": "task123", "name": "任务1"},
                "HAS_TASK"
            )
            
            # 通过节点ID匹配（不创建新节点）
            create_relationship(
                {"id": "4:abc123:0"},
                {"id": "4:def456:0"},
                "RELATED_TO",
                {"weight": 0.8},
                auto_create_nodes=False
            )
            
            # 混合：起始节点通过ID匹配，目标节点自动创建
            create_relationship(
                {"id": "4:abc123:0"},
                {"label": "File", "path": "/path/to/file.py", "name": "file.py"},
                "CONTAINS"
            )
        """
        # 构建节点 MERGE/MATCH 条件和参数
        if auto_create_nodes:
            from_clause, from_params = self._build_node_merge("a", from_node)
            to_clause, to_params = self._build_node_merge("b", to_node)
        else:
            from_clause, from_params = self._build_node_match("a", from_node)
            to_clause, to_params = self._build_node_match("b", to_node)
        
        # 构建关系属性
        rel_props = ""
        rel_params = {}
        if relationship_properties:
            props_str = ", ".join([f"{k}: $rel_{k}" for k in relationship_properties.keys()])
            rel_props = f" {{{props_str}}}"
            rel_params = {f"rel_{k}": v for k, v in relationship_properties.items()}
        
        # Neo4j 要求 MERGE 与 MATCH 之间必须用 WITH 传递变量
        query = f"""
        {from_clause}
        WITH a
        {to_clause}
        MERGE (a)-[r:{relationship_type}{rel_props}]->(b)
        RETURN r
        """
        
        # 合并所有参数
        parameters = {**from_params, **to_params, **rel_params}
        
        records = self.client.execute_write(query, parameters)
        if records:
            record = records[0]
            return dict(record["r"])
        return {}
    
    def update_node(
        self,
        node_spec: Dict,
        updates: Dict
    ) -> Dict:
        """
        更新节点的字段值
        
        Args:
            node_spec: 节点匹配条件
                       - 通过ID匹配: {"id": "element_id"}
                       - 通过标签和属性匹配: {"label": "Label", "key": "value", ...}
            updates: 要更新的字段字典，例如 {"name": "新名称", "status": "completed"}
            
        Returns:
            更新后的节点数据字典，如果节点不存在或更新失败则返回空字典
            
        Example:
            # 通过节点ID更新
            update_node(
                {"id": "4:abc123:0"},
                {"name": "新项目名称", "status": "active"}
            )
            
            # 通过标签和属性匹配并更新
            update_node(
                {"label": "Project", "task_id": "task123"},
                {"path": "/new/path", "updated_at": "2024-01-01"}
            )
            
            # 更新单个字段
            update_node(
                {"label": "Project", "name": "project1"},
                {"status": "completed"}
            )
        """
        if not updates:
            return {}
        
        # 构建节点匹配条件
        match_clause, match_params = self._build_node_match("n", node_spec)
        
        # 构建 SET 子句
        set_clauses = []
        update_params = {}
        for key, value in updates.items():
            param_key = f"update_{key}"
            set_clauses.append(f"n.{key} = ${param_key}")
            update_params[param_key] = value
        
        set_clause = ", ".join(set_clauses)
        
        query = f"""
        {match_clause}
        SET {set_clause}
        RETURN n
        """
        
        # 合并所有参数
        parameters = {**match_params, **update_params}
        
        records = self.client.execute_write(query, parameters)
        if records:
            record = records[0]
            return dict(record["n"])
        return {}
    
    def _build_node_match(self, alias: str, node_spec: Dict) -> tuple[str, Dict]:
        """
        构建节点匹配条件和参数（仅匹配，不创建）
        
        Args:
            alias: 节点别名
            node_spec: 节点规格，可以是 {"id": "element_id"} 或 {"label": "Label", "property": "value"}
            
        Returns:
            (Cypher 匹配语句片段, 参数字典)
        """
        node_spec = _normalize_node_spec(node_spec)
        if "id" in node_spec:
            # 通过 element_id 匹配
            param_key = f"{alias}_id"
            return f"MATCH ({alias}) WHERE elementId({alias}) = ${param_key}", {param_key: node_spec["id"]}
        elif "label" in node_spec:
            # 通过标签和属性匹配
            label = node_spec["label"]
            _skip = frozenset({"label", "id", "elementId"})
            props = {k: v for k, v in node_spec.items() if k not in _skip}
            if props:
                props_str = ", ".join([f"{k}: ${alias}_{k}" for k in props.keys()])
                match_clause = f"MATCH ({alias}:{label} {{{props_str}}})"
                params = {f"{alias}_{k}": v for k, v in props.items()}
                return match_clause, params
            else:
                return f"MATCH ({alias}:{label})", {}
        else:
            raise ValueError("节点规格必须包含 'id' 或 'label' 字段")
    
    def _build_node_merge(self, alias: str, node_spec: Dict) -> tuple[str, Dict]:
        """
        构建节点 MERGE 条件和参数（如果不存在则创建）
        
        Args:
            alias: 节点别名
            node_spec: 节点规格
                       - 通过ID匹配: {"id": "element_id"} (不创建新节点)
                       - 通过标签和属性匹配/创建: {"label": "Label", "key": "value", ...}
            
        Returns:
            (Cypher MERGE 语句片段, 参数字典)
        """
        node_spec = _normalize_node_spec(node_spec)
        if "id" in node_spec:
            # 通过 element_id 匹配（不创建新节点）
            param_key = f"{alias}_id"
            return f"MATCH ({alias}) WHERE elementId({alias}) = ${param_key}", {param_key: node_spec["id"]}
        elif "label" in node_spec:
            # 通过标签和属性 MERGE（不存在则创建）
            label = node_spec["label"]
            _skip = frozenset({"label", "id", "elementId"})
            props = {k: v for k, v in node_spec.items() if k not in _skip}
            
            if props:
                # 使用所有属性进行匹配和创建
                props_str = ", ".join([f"{k}: ${alias}_{k}" for k in props.keys()])
                merge_clause = f"MERGE ({alias}:{label} {{{props_str}}})"
                params = {f"{alias}_{k}": v for k, v in props.items()}
                return merge_clause, params
            else:
                # 只有标签，没有属性
                return f"MERGE ({alias}:{label})", {}
        else:
            raise ValueError("节点规格必须包含 'id' 或 'label' 字段")
    
    