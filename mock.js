#!/usr/bin/env node

var net = require('net');
var server = net.createServer(function(c) {
  console.log('server connected');
  c.on('end', function() {
    console.log('server disconnected');
  });
  c.on('data', function(d){
    console.log('recv: ' + d);
  });
});
server.listen(5678, function() {
  console.log('server bound');
});