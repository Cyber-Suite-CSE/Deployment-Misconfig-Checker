import graphene

class Query(graphene.ObjectType):
    hello = graphene.String(default_value="Hello from vulnerable GraphQL!")

schema = graphene.Schema(query=Query)