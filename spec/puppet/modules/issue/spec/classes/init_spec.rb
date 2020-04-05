require 'spec_helper'
describe 'issue' do

  context 'with defaults for all parameters' do
    it { should contain_class('issue') }
  end
end
