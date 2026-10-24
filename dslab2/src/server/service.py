from protos import pbft_pb2 as pbft
from protos import pbft_pb2_grpc
from server.node import Node

class PbftServicer(pbft_pb2_grpc.PbftServiceServicer):
    def __init__(self, node : Node):
        self.node = node

    def SendRequest(self, request, context):
        status = self.node.handle_request(request)
        return pbft.StringResponse(data=status)

    def SendPrePrepare(self, request, context):
        prepare = self.node.handle_pre_prepare(request)
        if prepare:
            return prepare
        return pbft.Prepare()

    def SendAggregatedPrepare(self, request, context):
        commit = self.node.handle_aggregated_prepare(request)
        if commit:
            return commit
        return pbft.Commit()

    def SendAggregatedCommit(self, request, context):
        self.node.handle_aggregated_commit(request)
        return pbft.Empty()

    def SendReply(self, request, context):
        return pbft.Empty()

    def SendViewChange(self, request, context):
        self.node.handle_view_change(request)
        return pbft.Empty()

    def SendNewView(self, request, context):
        self.node.handle_new_view(request)
        return pbft.Empty()

    def SendCheckpoint(self, request, context):
        self.node.handle_checkpoint(request)
        return pbft.Empty()

    def SetMode(self, request, context):
        self.node.set_mode(request.live, request.byzantine, request.attack)
        return pbft.Empty()

    def Reset(self, request, context):
        self.node.reset()
        return pbft.Empty()

    def PrintLog(self, request, context):
        return pbft.StringResponse(data=self.node.print_log())

    def PrintDB(self, request, context):
        return pbft.StringResponse(data=self.node.print_db())

    def PrintStatus(self, request, context):
        return pbft.StringResponse(data=self.node.print_status(request.seq))

    def PrintView(self, request, context):
        return pbft.StringResponse(data=self.node.print_view())