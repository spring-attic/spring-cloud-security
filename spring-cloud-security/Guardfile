require 'asciidoctor'
require 'erb'

options = {:mkdirs => true, :safe => :unsafe, :attributes => ['linkcss', 'allow-uri-read']}

guard 'shell' do
  watch(/^[A-Z-a-z][^#]*\.adoc$/) {|m|
    Asciidoctor.load_file('src/main/asciidoc/README.adoc', :to_file => './README.adoc', safe: :safe, parse: false, attributes: 'allow-uri-read')
    Asciidoctor.render_file('src/main/asciidoc/spring-cloud-security.adoc', options.merge(:to_dir => 'target/generated-docs'))
  }
end
