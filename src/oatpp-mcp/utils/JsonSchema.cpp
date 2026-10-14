//
// Created by Leonid S on 12/12/24.
//

#include "JsonSchema.hpp"
#include "oatpp/utils/Conversion.hpp"

namespace oatpp { namespace mcp { namespace utils {

ObjectSchemaMapper::ObjectSchemaMapper() {

  m_methods.resize(static_cast<size_t>(data::type::ClassId::getClassCount()), nullptr);

  setMapperMethod(data::type::__class::String::CLASS_ID, &ObjectSchemaMapper::mapString);
  setMapperMethod(data::type::__class::Tree::CLASS_ID, &ObjectSchemaMapper::mapTree);
  setMapperMethod(data::type::__class::Any::CLASS_ID, &ObjectSchemaMapper::mapAny);

  setMapperMethod(data::type::__class::Int8::CLASS_ID, &ObjectSchemaMapper::mapInteger);
  setMapperMethod(data::type::__class::UInt8::CLASS_ID, &ObjectSchemaMapper::mapInteger);

  setMapperMethod(data::type::__class::Int16::CLASS_ID, &ObjectSchemaMapper::mapInteger);
  setMapperMethod(data::type::__class::UInt16::CLASS_ID, &ObjectSchemaMapper::mapInteger);

  setMapperMethod(data::type::__class::Int32::CLASS_ID, &ObjectSchemaMapper::mapInteger);
  setMapperMethod(data::type::__class::UInt32::CLASS_ID, &ObjectSchemaMapper::mapInteger);

  setMapperMethod(data::type::__class::Int64::CLASS_ID, &ObjectSchemaMapper::mapInteger);
  setMapperMethod(data::type::__class::UInt64::CLASS_ID, &ObjectSchemaMapper::mapInteger);

  setMapperMethod(data::type::__class::Float32::CLASS_ID, &ObjectSchemaMapper::mapFloat);
  setMapperMethod(data::type::__class::Float64::CLASS_ID, &ObjectSchemaMapper::mapFloat);
  setMapperMethod(data::type::__class::Boolean::CLASS_ID, &ObjectSchemaMapper::mapBoolean);

  setMapperMethod(data::type::__class::AbstractObject::CLASS_ID, &ObjectSchemaMapper::mapObject);
  setMapperMethod(data::type::__class::AbstractEnum::CLASS_ID, &ObjectSchemaMapper::mapEnum);

  setMapperMethod(data::type::__class::AbstractVector::CLASS_ID, &ObjectSchemaMapper::mapCollection);
  setMapperMethod(data::type::__class::AbstractList::CLASS_ID, &ObjectSchemaMapper::mapCollection);
  setMapperMethod(data::type::__class::AbstractUnorderedSet::CLASS_ID, &ObjectSchemaMapper::mapCollection);

  setMapperMethod(data::type::__class::AbstractPairList::CLASS_ID, &ObjectSchemaMapper::mapMap);
  setMapperMethod(data::type::__class::AbstractUnorderedMap::CLASS_ID, &ObjectSchemaMapper::mapMap);

}

void ObjectSchemaMapper::setMapperMethod(const data::type::ClassId& classId, MapperMethod method) {
  const auto id = static_cast<v_uint32>(classId.id);
  if(id >= m_methods.size()) {
    m_methods.resize(id + 1, nullptr);
  }
  m_methods[id] = method;
}

void ObjectSchemaMapper::map(State& state, const oatpp::Type* type) const
{
  auto id = static_cast<v_uint32>(type->classId.id);
  auto& method = m_methods[id];
  if(method) {
    (*method)(this, state, type);
  } else {
    auto* interpretation = type->findInterpretation(state.config->enabledInterpretations);
    if(interpretation) {
      map(state, interpretation->getInterpretationType());
    } else {

      state.errorStack.push("[oatpp::data::mapping::ObjectSchemaMapper::map()]: "
                            "Error. No serialize method for type '" +
                            oatpp::String(type->classId.name) + "'");

      return;
    }
  }
}

oatpp::data::mapping::Tree ObjectSchemaMapper::map(const oatpp::Type* type, data::mapping::Tree& defs) const {

  data::mapping::Tree schema;
  std::unordered_set<oatpp::String> knownSchemas;
  mcp::utils::ObjectSchemaMapper::Config config;
  mcp::utils::ObjectSchemaMapper::State state;
  state.config = &config;
  state.tree = &schema;
  state.defs = &defs;
  state.knownSchemas = &knownSchemas;

  map(state, type);

  if(!state.errorStack.empty()) {
    throw oatpp::data::mapping::MappingError(std::move(state.errorStack));
  }

  return std::move(schema);

}

void ObjectSchemaMapper::mapBoolean(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {
  (*state.tree)["type"] = "boolean";
}

void ObjectSchemaMapper::mapFloat(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {
  (*state.tree)["type"] = "number";
}

void ObjectSchemaMapper::mapInteger(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {
  (*state.tree)["type"] = "integer";
}

void ObjectSchemaMapper::mapString(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {
  (*state.tree)["type"] = "string";
}

void ObjectSchemaMapper::mapTree(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {
  (*state.tree)["type"].setMap({});
}

void ObjectSchemaMapper::mapAny(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {
  (*state.tree)["type"].setMap({});
}

void ObjectSchemaMapper::mapEnum(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {

  oatpp::String typeName = type->nameQualifier;

  (*state.tree)["$ref"] = "#/$defs/" + typeName;

  auto it = state.knownSchemas->find(typeName);
  if(it != state.knownSchemas->end()) {
    return;
  }

  state.knownSchemas->insert(typeName);
  auto& currSchema = (*state.defs)[typeName];

  auto polymorphicDispatcher = static_cast<const data::type::__class::AbstractEnum::PolymorphicDispatcher*>(
    type->polymorphicDispatcher
  );

  data::type::EnumInterpreterError e = data::type::EnumInterpreterError::OK;
  // mapper->map(state, polymorphicDispatcher->getInterpretationType());

  auto values = polymorphicDispatcher->getInterpretedEnum(state.config->useUnqualifiedEnumNames);
  auto& enumValues = currSchema["enum"];
  enumValues.setVector(values.size());

  auto& oToTree = mapper->m_jsonMapper.objectToTreeMapper();

  for(v_uint32 i = 0; i < values.size(); i ++) {

    auto& anyV = values[i];

    data::mapping::ObjectToTreeMapper::Config config;
    data::mapping::ObjectToTreeMapper::State s;
    s.config = &config;
    s.tree = &enumValues[(int)i];

    oToTree.map(s, anyV);

  }

}

void ObjectSchemaMapper::mapCollection(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {

  auto dispatcher = static_cast<const data::type::__class::Collection::PolymorphicDispatcher*>(
    type->polymorphicDispatcher
  );

  (*state.tree)["type"] = "array";

  data::mapping::Tree& nested = (*state.tree)["items"];
  State nestedState;
  nestedState.tree = &nested;
  nestedState.defs = state.defs;
  nestedState.config = state.config;
  nestedState.knownSchemas = state.knownSchemas;

  mapper->map(nestedState, dispatcher->getItemType());

  if(!nestedState.errorStack.empty()) {
    state.errorStack.splice(nestedState.errorStack);
    state.errorStack.push("[oatpp::data::mapping::ObjectSchemaMapper::mapCollection()]: Can't describe items type");
    return;
  }

}

void ObjectSchemaMapper::mapMap(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {

  auto dispatcher = static_cast<const data::type::__class::Map::PolymorphicDispatcher*>(
    type->polymorphicDispatcher
  );

  auto keyType = dispatcher->getKeyType();
  if(keyType->classId != oatpp::String::Class::CLASS_ID){
    state.errorStack.push("[oatpp::data::mapping::ObjectSchemaMapper::mapMap()]: Invalid map key. Key should be String");
    return;
  }

  (*state.tree)["type"] = "object";

  data::mapping::Tree& nested = (*state.tree)["additionalProperties"];
  State nestedState;
  nestedState.tree = &nested;
  nestedState.defs = state.defs;
  nestedState.config = state.config;
  nestedState.knownSchemas = state.knownSchemas;

  mapper->map(nestedState, dispatcher->getValueType());

  if(!nestedState.errorStack.empty()) {
    state.errorStack.splice(nestedState.errorStack);
    state.errorStack.push("[oatpp::data::mapping::ObjectSchemaMapper::mapMap()]: Can't describe values type");
    return;
  }

}

void ObjectSchemaMapper::mapObject(const ObjectSchemaMapper* mapper, State& state, const oatpp::Type* type) {

  oatpp::String typeName = type->nameQualifier;

  (*state.tree)["$ref"] = "#/$defs/" + typeName;

  auto it = state.knownSchemas->find(typeName);
  if(it != state.knownSchemas->end()) {
    return;
  }

  state.knownSchemas->insert(typeName);

  auto& currSchema = (*state.defs)[typeName];

  auto dispatcher = static_cast<const oatpp::data::type::__class::AbstractObject::PolymorphicDispatcher*>(
    type->polymorphicDispatcher
  );
  auto fields = dispatcher->getProperties()->getList();
  currSchema["type"] = "object";

  auto& properties = currSchema["properties"];
  auto& required = currSchema["required"];
  required.setVector(0);

  for (auto const& field : fields) {

    oatpp::String key;
    state.config->useUnqualifiedFieldNames ? key = field->unqualifiedName : key = field->name;

    if(field->info.required) {
      data::mapping::Tree keyNode;
      keyNode = key;
      required.getVector().push_back(keyNode);
    }

    data::mapping::Tree& nested = (properties)[key];
    State nestedState;
    nestedState.tree = &nested;
    nestedState.defs = state.defs;
    nestedState.config = state.config;
    nestedState.knownSchemas = state.knownSchemas;

    mapper->map(nestedState, field->type);

    if(!nestedState.errorStack.empty()) {
      state.errorStack.splice(nestedState.errorStack);
      state.errorStack.push("[oatpp::data::mapping::ObjectSchemaMapper::mapObject()]: field='" + key + "'");
      return;
    }

  }


}

}}}
